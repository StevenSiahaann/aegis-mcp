"""Raw JSON-RPC 2.0 and MCP lifecycle dispatcher with global system error masking."""

from __future__ import annotations

import json
import time
from typing import Any

from aegis_mcp import __version__
from aegis_mcp.infrastructure.mcp_protocol.models import (
    DEFAULT_MCP_VERSION,
    JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    SUPPORTED_MCP_VERSIONS,
)
from aegis_mcp.infrastructure.mcp_protocol.registry import ToolRegistry
from aegis_mcp.infrastructure.observability.context import bind_trace_context
from aegis_mcp.infrastructure.observability.logger import NDJSONLogger


class MCPDispatcher:
    """Routes raw JSON-RPC 2.0 frames through the MCP lifecycle and tool registry."""

    def __init__(self, registry: ToolRegistry, logger: NDJSONLogger) -> None:
        self._registry = registry
        self._logger = logger
        self._initialized = False

    @staticmethod
    def _make_error_response(
        req_id: str | int | None,
        code: int,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        err_obj: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            err_obj["data"] = data
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": err_obj,
        }

    @staticmethod
    def _make_result_response(req_id: str | int | None, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result,
        }

    def handle_raw_line(self, line: str) -> str | None:
        """Process a single raw newline-delimited JSON-RPC frame and return JSON string or None."""
        stripped = line.strip()
        if not stripped:
            return None

        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            with bind_trace_context() as trace_ctx:
                self._logger.warn(
                    "JSONRPC_PARSE_ERROR",
                    f"Malformed JSON payload received: {exc.msg}",
                    context={"pos": exc.pos},
                )
                resp = self._make_error_response(
                    None,
                    JSONRPC_PARSE_ERROR,
                    "Parse error: invalid JSON payload",
                    data={"trace_id": trace_ctx.trace_id},
                )
                return json.dumps(resp, separators=(",", ":"))

        if not isinstance(payload, dict):
            with bind_trace_context() as trace_ctx:
                resp = self._make_error_response(
                    None,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: top-level JSON value must be an object",
                    data={"trace_id": trace_ctx.trace_id},
                )
                return json.dumps(resp, separators=(",", ":"))

        resp_dict = self.dispatch_object(payload)
        if resp_dict is None:
            return None
        return json.dumps(resp_dict, separators=(",", ":"))

    def dispatch_object(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Dispatch a parsed JSON-RPC 2.0 request or notification object."""
        jsonrpc_ver = payload.get("jsonrpc")
        has_id = "id" in payload
        req_id = payload.get("id")
        method = payload.get("method")
        params = payload.get("params")

        # Extract optional W3C traceparent from params._meta
        traceparent: str | None = None
        if isinstance(params, dict):
            meta = params.get("_meta")
            if isinstance(meta, dict) and isinstance(meta.get("traceparent"), str):
                traceparent = meta["traceparent"]

        with bind_trace_context(traceparent=traceparent, request_id=req_id) as trace_ctx:
            if jsonrpc_ver != "2.0" or not isinstance(method, str) or not method:
                return self._make_error_response(
                    req_id if isinstance(req_id, (str, int)) else None,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: 'jsonrpc' must be '2.0' and 'method' must be a non-empty string",
                    data={"trace_id": trace_ctx.trace_id},
                )

            if has_id and req_id is not None and not isinstance(req_id, (str, int)):
                return self._make_error_response(
                    None,
                    JSONRPC_INVALID_REQUEST,
                    "Invalid Request: 'id' must be a string, integer, or null",
                    data={"trace_id": trace_ctx.trace_id},
                )

            if params is not None and not isinstance(params, dict):
                if not has_id:
                    return None
                return self._make_error_response(
                    req_id,
                    JSONRPC_INVALID_PARAMS,
                    "Invalid params: 'params' must be a JSON object",
                    data={"trace_id": trace_ctx.trace_id},
                )

            params_dict: dict[str, Any] = params if isinstance(params, dict) else {}

            # Notifications (no "id" field present in JSON-RPC request) produce no response
            if not has_id:
                self._handle_notification(method, params_dict)
                return None

            start_ns = time.perf_counter_ns()
            try:
                return self._handle_request(req_id, method, params_dict, trace_ctx.trace_id)
            except Exception as exc:
                duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
                self._logger.error(
                    "UNHANDLED_SYSTEM_EXCEPTION",
                    f"Unexpected internal error in method '{method}': {type(exc).__name__}",
                    context={"method": method, "error_type": type(exc).__name__},
                    duration_ms=duration_ms,
                )
                return self._make_error_response(
                    req_id,
                    JSONRPC_INTERNAL_ERROR,
                    "An unexpected internal system error occurred",
                    data={"trace_id": trace_ctx.trace_id},
                )

    def _handle_notification(self, method: str, params: dict[str, Any]) -> None:
        if method == "notifications/initialized":
            self._initialized = True
            self._logger.info("MCP_CLIENT_INITIALIZED", "MCP client completed initialization handshake")
        elif method == "notifications/cancelled":
            self._logger.info(
                "MCP_REQUEST_CANCELLED",
                "Client sent cancellation notification",
                context={"requestId": params.get("requestId")},
            )

    def _handle_request(
        self,
        req_id: str | int | None,
        method: str,
        params: dict[str, Any],
        trace_id: str,
    ) -> dict[str, Any]:
        if method == "initialize":
            client_version = params.get("protocolVersion")
            negotiated_version = (
                client_version
                if isinstance(client_version, str) and client_version in SUPPORTED_MCP_VERSIONS
                else DEFAULT_MCP_VERSION
            )
            self._initialized = True
            self._logger.info(
                "MCP_INITIALIZE",
                f"Handshake negotiated protocolVersion={negotiated_version}",
                context={
                    "clientInfo": params.get("clientInfo"),
                    "protocolVersion": negotiated_version,
                },
                is_audit_event=True,
            )
            return self._make_result_response(
                req_id,
                {
                    "protocolVersion": negotiated_version,
                    "capabilities": {
                        "tools": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": "aegis-mcp",
                        "version": __version__,
                    },
                },
            )

        if method == "ping":
            return self._make_result_response(req_id, {})

        if method == "tools/list":
            return self._make_result_response(
                req_id,
                {"tools": self._registry.list_tool_descriptors()},
            )

        if method == "resources/list":
            return self._make_result_response(req_id, {"resources": []})

        if method == "prompts/list":
            return self._make_result_response(req_id, {"prompts": []})

        if method == "tools/call":
            tool_name = params.get("name")
            if not isinstance(tool_name, str) or not tool_name:
                return self._make_error_response(
                    req_id,
                    JSONRPC_INVALID_PARAMS,
                    "Invalid params: 'name' must be a non-empty string",
                    data={"trace_id": trace_id},
                )
            if not self._registry.has_tool(tool_name):
                return self._make_error_response(
                    req_id,
                    JSONRPC_INVALID_PARAMS,
                    f"Unknown tool: '{tool_name}'",
                    data={"trace_id": trace_id, "tool": tool_name},
                )

            raw_args = params.get("arguments")
            if raw_args is not None and not isinstance(raw_args, dict):
                return self._make_error_response(
                    req_id,
                    JSONRPC_INVALID_PARAMS,
                    "Invalid params: 'arguments' must be a JSON object",
                    data={"trace_id": trace_id, "tool": tool_name},
                )

            tool_result = self._registry.call_tool(tool_name, raw_args)
            return self._make_result_response(req_id, tool_result)

        return self._make_error_response(
            req_id,
            JSONRPC_METHOD_NOT_FOUND,
            f"Method not found: '{method}'",
            data={"trace_id": trace_id},
        )

