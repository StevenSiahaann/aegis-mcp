"""Use-case handler for executing allowlisted binaries without shell interpolation."""

from __future__ import annotations

from aegis_mcp.application.ports import ExecutionResult, SandboxRunnerPort
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.matchers import CommandArgumentGuard
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Result


class RunCommandHandler:
    """Executes allowlisted commands with shell=False, argument guards, and process-group isolation."""

    def __init__(self, runner: SandboxRunnerPort, policy: SandboxPolicy) -> None:
        self._runner = runner
        self._policy = policy

    def execute(
        self,
        binary: str,
        *,
        args: list[str] | None = None,
        cwd: str = ".",
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]:
        if not self._policy.allow_exec:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_EXEC_DISABLED,
                    title="Sandbox Command Execution Disabled",
                    detail=(
                        "Command execution is disabled under the active sandbox policy. "
                        "Launch with '--allow-exec' to enable isolated execution tools."
                    ),
                    is_security_violation=True,
                )
            )

        validation = CommandArgumentGuard.validate(binary, args or [], self._policy)
        if validation.is_err:
            return Err(validation.unwrap_err())

        clean_bin, clean_args = validation.unwrap()
        clamped_timeout = self._policy.clamp_timeout(timeout_seconds)
        return self._runner.run_command(
            clean_bin,
            args=clean_args,
            cwd_rel=cwd,
            timeout_seconds=clamped_timeout,
        )

