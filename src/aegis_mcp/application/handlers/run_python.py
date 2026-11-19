"""Use-case handler for executing Python snippets inside the OS sandbox."""

from __future__ import annotations

from aegis_mcp.application.ports import ExecutionResult, SandboxRunnerPort
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Result


class RunPythonHandler:
    """Executes Python code in a scrubbed environment with rlimits and process-group timeout."""

    def __init__(self, runner: SandboxRunnerPort, policy: SandboxPolicy) -> None:
        self._runner = runner
        self._policy = policy

    def execute(
        self,
        code: str,
        *,
        args: list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]:
        if not self._policy.allow_exec:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_EXEC_DISABLED,
                    title="Sandbox Code Execution Disabled",
                    detail=(
                        "Code execution is disabled under the active sandbox policy. "
                        "Launch with '--allow-exec' to enable isolated execution tools."
                    ),
                    is_security_violation=True,
                )
            )
        if not code or not code.strip():
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Empty Python Code",
                    detail="Python code snippet must not be empty.",
                )
            )
        if "\x00" in code:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_DANGEROUS_ARGUMENTS,
                    title="Null Byte In Code Snippet",
                    detail="Python code contains an illegal null byte.",
                    is_security_violation=True,
                )
            )

        clamped_timeout = self._policy.clamp_timeout(timeout_seconds)
        return self._runner.run_python(
            code,
            args=args or [],
            timeout_seconds=clamped_timeout,
        )

