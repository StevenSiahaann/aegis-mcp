"""Newline-delimited JSON-RPC 2.0 over stdio server loop."""

from __future__ import annotations

import sys
from typing import TextIO

from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.dispatcher import MCPDispatcher
from aegis_mcp.infrastructure.mcp_protocol.registry import ToolRegistry
from aegis_mcp.infrastructure.observability.logger import NDJSONLogger
from aegis_mcp.infrastructure.observability.metrics import InMemoryTelemetry
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem
from aegis_mcp.infrastructure.os_sandbox.selector_runner import SelectorSandboxRunner


class StdioMCPServer:
    """Zero-SDK MCP stdio transport binding stdin/stdout strictly to JSON-RPC 2.0 frames."""

    def __init__(
        self,
        policy: SandboxPolicy,
        *,
        in_stream: TextIO | None = None,
        out_stream: TextIO | None = None,
        err_stream: TextIO | None = None,
        logger: NDJSONLogger | None = None,
    ) -> None:
        self._policy = policy
        self._in = in_stream if in_stream is not None else sys.stdin
        self._out = out_stream if out_stream is not None else sys.stdout
        self._logger = (
            logger
            if logger is not None
            else NDJSONLogger(service_name="aegis-mcp", stream=err_stream or sys.stderr)
        )
        self._telemetry = InMemoryTelemetry()
        self._fs = PosixJailFileSystem(policy)
        self._runner = SelectorSandboxRunner(policy=policy, fs=self._fs)
        self._registry = ToolRegistry(
            policy=policy,
            fs=self._fs,
            runner=self._runner,
            telemetry=self._telemetry,
            logger=self._logger,
        )
        self._dispatcher = MCPDispatcher(registry=self._registry, logger=self._logger)

    @property
    def dispatcher(self) -> MCPDispatcher:
        return self._dispatcher

    @property
    def telemetry(self) -> InMemoryTelemetry:
        return self._telemetry

    def serve_forever(self) -> None:
        """Read newline-delimited JSON-RPC requests from in_stream until EOF."""
        protocol_out = self._out
        original_stdout = sys.stdout
        if protocol_out is sys.stdout:
            sys.stdout = sys.stderr

        self._logger.info(
            "SERVER_STARTED",
            "aegis-mcp stdio server listening",
            context={
                "workspace_root": str(self._policy.workspace_root),
                "allow_write": self._policy.allow_write,
                "allow_exec": self._policy.allow_exec,
            },
            is_audit_event=True,
        )
        try:
            for line in self._in:
                response_str = self._dispatcher.handle_raw_line(line)
                if response_str is not None:
                    protocol_out.write(response_str + "\n")
                    protocol_out.flush()
        except KeyboardInterrupt:
            pass
        finally:
            if protocol_out is original_stdout:
                sys.stdout = original_stdout
            self._logger.info("SERVER_STOPPED", "aegis-mcp stdio server shut down cleanly")

