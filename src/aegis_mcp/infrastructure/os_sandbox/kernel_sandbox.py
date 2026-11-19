"""Kernel-enforced sandbox drivers: macOS Seatbelt (sandbox-exec) and Linux bubblewrap.

The path jail in posix_fs only constrains the fs_* tools. Anything that executes code
(exec_python, pytest conftest, git hooks) must be confined by the kernel, otherwise it can
read or exfiltrate any file the user can. Both drivers here are deny-by-default for reads
outside the workspace and runtime prefixes, writes outside the workspace, and network.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from aegis_mcp.domain.matchers import SensitiveFileMatcher
from aegis_mcp.domain.policy import SandboxPolicy

# System locations a typical interpreter or toolchain needs to read on macOS.
_DARWIN_SYSTEM_READ_PATHS: tuple[str, ...] = (
    "/System",
    "/usr",
    "/bin",
    "/sbin",
    "/Library",
    "/opt",
    "/private/etc",
    "/private/var/db",
    "/dev",
)

# Basename patterns (POSIX ERE) the kernel must refuse to read even inside the workspace.
_SEATBELT_DENY_READ_REGEXES: tuple[str, ...] = (
    r"/\.env(\.[^/]*)?$",
    r"/\.envrc$",
    r"\.(pem|key|p12|pfx|jks|keystore|kdbx)$",
    r"\.tfstate(\.backup)?$",
    r"\.tfvars$",
    r"/id_(rsa|ed25519|ecdsa|dsa)[^/]*$",
    r"/\.(npmrc|pypirc|netrc|pgpass|htpasswd)$",
    r"/[^/]*(credentials|service-account|client_secret)[^/]*\.json$",
)

_SEATBELT_ALLOW_READ_REGEXES: tuple[str, ...] = (r"/\.env\.(example|template|sample|dist)$",)

# Paths inside the workspace that sandboxed code must never be able to modify, because
# the host later executes or trusts them outside the sandbox (git hooks/config, CI workflows, direnv, IDE tasks).
_WRITE_PROTECTED_SUBPATHS: tuple[str, ...] = (".git", ".github", ".vscode", ".idea")
_WRITE_PROTECTED_LITERALS: tuple[str, ...] = (".git/config", ".envrc")

_SKIP_SCAN_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".aegis-sandbox"}
)


def _sb_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _runtime_read_roots() -> list[str]:
    """Interpreter prefixes the sandboxed Python must be able to load modules from."""
    roots = {os.path.realpath(sys.prefix), os.path.realpath(sys.base_prefix)}
    return sorted(roots)


class KernelSandboxDriver(Protocol):
    @property
    def name(self) -> str: ...

    def wrap(self, argv: list[str], *, cwd: Path) -> list[str]: ...


@dataclass(frozen=True, slots=True)
class SeatbeltDriver:
    """macOS sandbox-exec driver with a deny-default SBPL profile."""

    policy: SandboxPolicy
    binary: str

    @property
    def name(self) -> str:
        return "seatbelt"

    def build_profile(self) -> str:
        ws = str(self.policy.workspace_root)
        scratch = str(self.policy.sandbox_scratch_dir)
        extra_reads = [str(p) for p in self.policy.extra_read_paths]
        read_roots = [*_DARWIN_SYSTEM_READ_PATHS, ws, *_runtime_read_roots(), *extra_reads]
        read_clause = " ".join(f"(subpath {_sb_string(p)})" for p in read_roots)

        lines = [
            "(version 1)",
            "(deny default)",
            "(deny network*)",
            "(allow process-exec)",
            "(allow signal (target same-sandbox))",
            "(allow sysctl-read)",
            # stat() anywhere is needed for path resolution; it reveals existence, not content.
            "(allow file-read-metadata)",
            f'(allow file-read* (literal "/") {read_clause})',
        ]
        if self.policy.allow_subprocess:
            lines.append("(allow process-fork)")

        deny_regex = " ".join(f'(regex #"{rx}")' for rx in _SEATBELT_DENY_READ_REGEXES)
        allow_regex = " ".join(f'(regex #"{rx}")' for rx in _SEATBELT_ALLOW_READ_REGEXES)
        lines.append(f"(deny file-read* {deny_regex})")
        lines.append(f"(allow file-read* {allow_regex})")

        if self.policy.allow_write:
            lines.append(f"(allow file-write* (subpath {_sb_string(ws)}))")
            protected = [f"(subpath {_sb_string(f'{ws}/{p}')})" for p in _WRITE_PROTECTED_SUBPATHS]
            protected += [f"(literal {_sb_string(f'{ws}/{p}')})" for p in _WRITE_PROTECTED_LITERALS]
            lines.append(f"(deny file-write* {' '.join(protected)})")
            lines.append(f"(deny file-write* {deny_regex})")
            lines.append(f"(allow file-write* {allow_regex})")
        lines.append(f"(allow file-write* (subpath {_sb_string(scratch)}))")
        lines.append('(allow file-write-data (literal "/dev/null"))')
        lines.append('(allow file-ioctl (literal "/dev/null"))')
        # Network stays denied by (deny default); no explicit allow is emitted.
        return "\n".join(lines) + "\n"

    def wrap(self, argv: list[str], *, cwd: Path) -> list[str]:
        return [self.binary, "-p", self.build_profile(), *argv]


def _iter_sensitive_files(root: Path, limit: int = 2000) -> Iterator[Path]:
    """Bounded iterative scan for sensitive files that bubblewrap must mask."""
    stack: list[Path] = [root]
    seen = 0
    while stack and seen < limit:
        current = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            seen += 1
            if entry.is_symlink():
                continue
            path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in _SKIP_SCAN_DIRS:
                    stack.append(path)
                continue
            rel = path.relative_to(root).as_posix()
            if SensitiveFileMatcher.is_sensitive(rel)[0]:
                yield path


@dataclass(frozen=True, slots=True)
class BubblewrapDriver:
    """Linux bubblewrap driver: empty mount namespace, no network, private PID namespace.

    --unshare-pid together with --die-with-parent means every process in the sandbox,
    including ones that called setsid(), is killed by the kernel once bwrap exits.
    """

    policy: SandboxPolicy
    binary: str

    @property
    def name(self) -> str:
        return "bubblewrap"

    def wrap(self, argv: list[str], *, cwd: Path) -> list[str]:
        ws = str(self.policy.workspace_root)
        scratch = str(self.policy.sandbox_scratch_dir)
        args = [
            self.binary,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind-try", "/bin", "/bin",
            "--ro-bind-try", "/sbin", "/sbin",
            "--ro-bind-try", "/lib", "/lib",
            "--ro-bind-try", "/lib64", "/lib64",
            "--ro-bind-try", "/etc", "/etc",
            "--proc", "/proc",
            "--dev", "/dev",
            "--tmpfs", "/tmp",
        ]
        for prefix in _runtime_read_roots():
            args += ["--ro-bind-try", prefix, prefix]
        for extra_p in self.policy.extra_read_paths:
            ep_str = str(extra_p)
            args += ["--ro-bind-try", ep_str, ep_str]
        args += ["--bind" if self.policy.allow_write else "--ro-bind", ws, ws]
        args += ["--bind", scratch, scratch]
        for rel in (*_WRITE_PROTECTED_SUBPATHS, *_WRITE_PROTECTED_LITERALS):
            target = self.policy.workspace_root / rel
            if target.exists():
                args += ["--ro-bind", str(target), str(target)]
        for sensitive in _iter_sensitive_files(self.policy.workspace_root):
            args += ["--ro-bind", "/dev/null", str(sensitive)]
        args += ["--chdir", str(cwd), "--", *argv]
        return args


@functools.lru_cache(maxsize=4)
def _bwrap_usable(binary: str) -> bool:
    """Probe once: unprivileged user namespaces may be disabled (e.g. Ubuntu AppArmor policy)."""
    try:
        probe = subprocess.run(
            [binary, "--unshare-all", "--ro-bind", "/", "/", "--", "/bin/true"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return probe.returncode == 0


def select_kernel_sandbox(policy: SandboxPolicy) -> KernelSandboxDriver | None:
    """Return the kernel sandbox driver for this platform, or None if unavailable."""
    if sys.platform == "darwin":
        binary = shutil.which("sandbox-exec") or (
            "/usr/bin/sandbox-exec" if os.path.exists("/usr/bin/sandbox-exec") else None
        )
        return SeatbeltDriver(policy=policy, binary=binary) if binary else None
    if sys.platform.startswith("linux"):
        binary = shutil.which("bwrap")
        if binary and _bwrap_usable(binary):
            return BubblewrapDriver(policy=policy, binary=binary)
    return None

