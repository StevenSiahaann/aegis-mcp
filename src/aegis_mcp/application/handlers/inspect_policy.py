"""Use-case handler for inspecting the active sandbox policy and RED telemetry snapshot."""

from __future__ import annotations

import sys
from typing import Any

from aegis_mcp.application.ports import TelemetryPort
from aegis_mcp.domain.errors import DomainError
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Ok, Result


class InspectPolicyHandler:
    """Returns transparent security policy boundaries and runtime RED telemetry."""

    def __init__(self, policy: SandboxPolicy, telemetry: TelemetryPort) -> None:
        self._policy = policy
        self._telemetry = telemetry

    def execute(self) -> Result[dict[str, Any], DomainError]:
        report: dict[str, Any] = {
            "workspace_root": str(self._policy.workspace_root),
            "platform": sys.platform,
            "capabilities": {
                "allow_write": self._policy.allow_write,
                "allow_exec": self._policy.allow_exec,
                "allow_symlinks_within_jail": self._policy.allow_symlinks_within_jail,
                "enable_seatbelt": self._policy.enable_seatbelt,
                "wrap_untrusted_content": self._policy.wrap_untrusted_content,
            },
            "limits": {
                "max_read_bytes": self._policy.max_read_bytes,
                "max_write_bytes": self._policy.max_write_bytes,
                "max_output_bytes": self._policy.max_output_bytes,
                "default_timeout_seconds": self._policy.default_timeout_seconds,
                "max_timeout_seconds": self._policy.max_timeout_seconds,
                "max_dir_depth": self._policy.max_dir_depth,
                "max_search_results": self._policy.max_search_results,
                "rlimit_cpu_seconds": self._policy.rlimit_cpu_seconds,
                "rlimit_fsize_bytes": self._policy.rlimit_fsize_bytes,
                "rlimit_nofile": self._policy.rlimit_nofile,
            },
            "allowed_binaries": sorted(self._policy.allowed_binaries),
            "extra_read_paths": [str(p) for p in self._policy.extra_read_paths],
            "telemetry": self._telemetry.snapshot(),
        }
        return Ok(report)

