"""Subprocess runner with process-group isolation (setsid + killpg), non-blocking selectors I/O loop, and monotonic watchdog."""

from __future__ import annotations

import contextlib
import os
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from aegis_mcp.application.ports import ExecutionResult
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.matchers import SecretRedactor
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result
from aegis_mcp.domain.uuidv7 import generate_uuidv7
from aegis_mcp.infrastructure.observability.context import get_current_trace_context
from aegis_mcp.infrastructure.os_sandbox.env_builder import CleanEnvironmentBuilder
from aegis_mcp.infrastructure.os_sandbox.kernel_sandbox import select_kernel_sandbox
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem
from aegis_mcp.infrastructure.os_sandbox.rlimits import make_preexec_limiter


class SelectorSandboxRunner:
    """Executes subprocesses in isolated sessions with non-blocking pipe draining and hard timeouts."""

    def __init__(self, policy: SandboxPolicy, fs: PosixJailFileSystem) -> None:
        self._policy = policy
        self._fs = fs
        self._lock = threading.Lock()
        self._active_pids: dict[str | int, int] = {}
        self._cancelled_requests: set[str | int] = set()

    def cancel_request(self, request_id: str | int) -> bool:
        """Cancel an in-flight execution by its JSON-RPC request_id via process-group SIGKILL."""
        with self._lock:
            self._cancelled_requests.add(request_id)
            pid = self._active_pids.get(request_id)
        if pid is not None:
            self._kill_process_group(pid)
            return True
        return False

    @staticmethod
    def _kill_process_group(pid: int) -> None:
        """Deliver SIGKILL to the entire child process group to eliminate orphan grandchildren."""
        try:
            pgid = os.getpgid(pid)
            os.killpg(pgid, signal.SIGKILL)
        except OSError:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)

    def _execute_argv(
        self,
        argv: list[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        command_summary: str,
    ) -> Result[ExecutionResult, DomainError]:
        clean_env = CleanEnvironmentBuilder.build(self._policy)

        effective_argv = list(argv)
        if self._policy.enable_seatbelt or self._policy.require_kernel_sandbox:
            kernel_driver = select_kernel_sandbox(self._policy)
            if kernel_driver is None:
                if self._policy.require_kernel_sandbox:
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_KERNEL_SANDBOX_UNAVAILABLE,
                            title="Kernel Sandbox Driver Unavailable (Fail-Closed)",
                            detail=(
                                "No OS kernel sandbox backend (macOS sandbox-exec or Linux bubblewrap) "
                                "is available on this host, and require_kernel_sandbox is enabled."
                            ),
                            is_security_violation=True,
                        )
                    )
            else:
                effective_argv = kernel_driver.wrap(effective_argv, cwd=cwd)

        cpu_limit = max(int(timeout_seconds) + 2, self._policy.rlimit_cpu_seconds)
        preexec = make_preexec_limiter(
            cpu_seconds=cpu_limit,
            fsize_bytes=self._policy.rlimit_fsize_bytes,
            nofile=self._policy.rlimit_nofile,
            as_bytes=self._policy.rlimit_as_bytes,
        )

        start_ns = time.perf_counter_ns()
        deadline = time.monotonic() + timeout_seconds

        try:
            proc = subprocess.Popen(
                effective_argv,
                cwd=str(cwd),
                env=clean_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
                close_fds=True,
                preexec_fn=preexec,
            )
        except OSError as exc:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_EXEC_FAILED,
                    title="Subprocess Spawn Failed",
                    detail=f"Failed to start '{command_summary}': {exc.strerror}",
                    context={"command": command_summary},
                )
            )

        assert proc.stdout is not None
        assert proc.stderr is not None

        req_id = get_current_trace_context().request_id
        if req_id is not None:
            with self._lock:
                self._active_pids[req_id] = proc.pid
                if req_id in self._cancelled_requests:
                    self._kill_process_group(proc.pid)

        stdout_fd = proc.stdout.fileno()
        stderr_fd = proc.stderr.fileno()
        os.set_blocking(stdout_fd, False)
        os.set_blocking(stderr_fd, False)

        stdout_buf = bytearray()
        stderr_buf = bytearray()
        max_bytes = self._policy.max_output_bytes
        stdout_truncated = False
        stderr_truncated = False
        timed_out = False
        cancelled = False

        sel = selectors.DefaultSelector()
        sel.register(stdout_fd, selectors.EVENT_READ, data="stdout")
        sel.register(stderr_fd, selectors.EVENT_READ, data="stderr")

        try:
            while sel.get_map():
                if req_id is not None:
                    with self._lock:
                        if req_id in self._cancelled_requests:
                            cancelled = True
                            timed_out = True
                            self._kill_process_group(proc.pid)
                            break

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    self._kill_process_group(proc.pid)
                    break

                events = sel.select(timeout=min(remaining, 0.05))
                if not events and proc.poll() is not None:
                    # Process exited; perform one final non-blocking drain pass
                    events = sel.select(timeout=0.0)
                    if not events:
                        break

                for key, _ in events:
                    fd = key.fd
                    stream_name = key.data
                    try:
                        chunk = os.read(fd, 8192)
                    except BlockingIOError:
                        continue
                    except OSError:
                        sel.unregister(fd)
                        continue

                    if not chunk:
                        sel.unregister(fd)
                        continue

                    if stream_name == "stdout":
                        if len(stdout_buf) < max_bytes:
                            space = max_bytes - len(stdout_buf)
                            stdout_buf.extend(chunk[:space])
                            if len(chunk) > space:
                                stdout_truncated = True
                        else:
                            stdout_truncated = True
                    else:
                        if len(stderr_buf) < max_bytes:
                            space = max_bytes - len(stderr_buf)
                            stderr_buf.extend(chunk[:space])
                            if len(chunk) > space:
                                stderr_truncated = True
                        else:
                            stderr_truncated = True

            # Wait for process termination after pipes close or timeout kill
            try:
                remaining_wait = max(0.05, deadline - time.monotonic()) if not timed_out else 0.5
                proc.wait(timeout=remaining_wait)
            except subprocess.TimeoutExpired:
                timed_out = True
                self._kill_process_group(proc.pid)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=0.5)
            finally:
                # Ensure any lingering grandchild processes in the session group are cleaned up
                self._kill_process_group(proc.pid)
                if req_id is not None:
                    with self._lock:
                        if req_id in self._cancelled_requests:
                            cancelled = True
                            timed_out = True
        finally:
            if req_id is not None:
                with self._lock:
                    self._active_pids.pop(req_id, None)
                    self._cancelled_requests.discard(req_id)
            sel.close()
            proc.stdout.close()
            proc.stderr.close()

        duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        raw_stdout = stdout_buf.decode("utf-8", errors="replace")
        raw_stderr = stderr_buf.decode("utf-8", errors="replace")

        if stdout_truncated:
            raw_stdout += f"\n... [AEGIS SANDBOX: stdout truncated at {max_bytes} bytes limit] ..."
        if stderr_truncated:
            raw_stderr += f"\n... [AEGIS SANDBOX: stderr truncated at {max_bytes} bytes limit] ..."

        clean_stdout, out_redactions = SecretRedactor.redact_text(raw_stdout)
        clean_stderr, err_redactions = SecretRedactor.redact_text(raw_stderr)
        total_redactions = out_redactions + err_redactions

        if timed_out:
            reason_title = (
                "Execution Cancelled By Client (Process Group SIGKILL)"
                if cancelled
                else "Execution Timed Out (Process Group SIGKILL)"
            )
            return Err(
                DomainError(
                    code=ErrorCode.ERR_EXEC_TIMEOUT,
                    title=reason_title,
                    detail=(
                        f"Execution of '{command_summary}' was terminated via process-group SIGKILL "
                        f"(cancelled={cancelled}, timeout={timeout_seconds:.2f}s)."
                    ),
                    context={
                        "command": command_summary,
                        "cancelled": cancelled,
                        "timeout_seconds": timeout_seconds,
                        "duration_ms": round(duration_ms, 2),
                        "partial_stdout": clean_stdout,
                        "partial_stderr": clean_stderr,
                    },
                )
            )

        exit_code = proc.returncode if proc.returncode is not None else -9

        return Ok(
            ExecutionResult(
                command_summary=command_summary,
                exit_code=exit_code,
                stdout=clean_stdout,
                stderr=clean_stderr,
                duration_ms=round(duration_ms, 3),
                timed_out=False,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                secrets_redacted=total_redactions,
            )
        )

    def run_python(
        self,
        code: str,
        *,
        args: list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]:
        scratch_dir = self._policy.sandbox_scratch_dir
        scratch_dir.mkdir(parents=True, exist_ok=True)
        script_path = scratch_dir / f"exec_{generate_uuidv7().hex}.py"

        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(script_path), flags, 0o600)
            try:
                os.write(fd, code.encode("utf-8"))
            finally:
                os.close(fd)

            effective_timeout = self._policy.clamp_timeout(timeout_seconds)
            argv = [sys.executable, "-B", str(script_path), *(args or [])]
            return self._execute_argv(
                argv,
                cwd=self._policy.workspace_root,
                timeout_seconds=effective_timeout,
                command_summary="python3 <sandbox_snippet>",
            )
        finally:
            with contextlib.suppress(OSError):
                if os.path.lexists(script_path):
                    os.unlink(script_path)

    def run_command(
        self,
        binary: str,
        *,
        args: list[str] | None = None,
        cwd_rel: str = ".",
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]:
        cwd_res = self._fs.resolve_safe_path(
            cwd_rel,
            must_exist=True,
            allow_directory=True,
            check_sensitive=True,
        )
        if cwd_res.is_err:
            return Err(cwd_res.unwrap_err())

        target_cwd = cwd_res.unwrap()
        if not target_cwd.is_dir():
            return Err(
                DomainError(
                    code=ErrorCode.ERR_NOT_A_DIRECTORY,
                    title="Working Directory Is Not A Directory",
                    detail=f"Requested cwd '{cwd_rel}' is not a directory.",
                )
            )

        clean_env = CleanEnvironmentBuilder.build(self._policy)
        resolved_bin = shutil.which(binary, path=clean_env["PATH"])
        if not resolved_bin:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_EXEC_FAILED,
                    title="Allowlisted Binary Not Found On System",
                    detail=f"Allowlisted binary '{binary}' could not be located in sandbox PATH.",
                    context={"binary": binary},
                )
            )

        effective_timeout = self._policy.clamp_timeout(timeout_seconds)
        arg_list = args or []
        argv = [resolved_bin, *arg_list]
        summary = f"{binary} {' '.join(arg_list)}".strip()

        return self._execute_argv(
            argv,
            cwd=target_cwd,
            timeout_seconds=effective_timeout,
            command_summary=summary,
        )
