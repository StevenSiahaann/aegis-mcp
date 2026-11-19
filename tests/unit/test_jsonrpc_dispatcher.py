"""Unit tests for raw JSON-RPC 2.0 protocol framing, handshake, and error distinction."""

from __future__ import annotations

import io
import json
from pathlib import Path

from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.models import (
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
)
from aegis_mcp.infrastructure.mcp_protocol.stdio_server import StdioMCPServer


def _make_server(tmp_path: Path) -> StdioMCPServer:
    policy = SandboxPolicy(workspace_root=tmp_path, allow_write=False, allow_exec=False)
    err_buf = io.StringIO()
    return StdioMCPServer(policy=policy, err_stream=err_buf)


def test_jsonrpc_initialize_and_tools_list(tmp_path: Path) -> None:
    # 1. ARRANGE
    server = _make_server(tmp_path)
    init_req = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "pytest-client", "version": "1.0.0"},
            },
        }
    )
    notif_req = json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})
    list_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})

    # 2. ACT
    init_raw = server.dispatcher.handle_raw_line(init_req)
    notif_raw = server.dispatcher.handle_raw_line(notif_req)
    list_raw = server.dispatcher.handle_raw_line(list_req)

    # 3. ASSERT
    assert init_raw is not None
    init_resp = json.loads(init_raw)
    assert init_resp["id"] == 1
    assert init_resp["result"]["protocolVersion"] == "2024-11-05"
    assert init_resp["result"]["serverInfo"]["name"] == "aegis-mcp"
    assert notif_raw is None
    assert list_raw is not None
    list_resp = json.loads(list_raw)
    tool_names = [t["name"] for t in list_resp["result"]["tools"]]
    assert len(tool_names) == 8
    assert "fs_read_file" in tool_names
    assert "exec_python" in tool_names


def test_jsonrpc_protocol_error_codes_vs_domain_is_error(tmp_path: Path) -> None:
    # 1. ARRANGE
    server = _make_server(tmp_path)

    # 2. ACT
    parse_err_raw = server.dispatcher.handle_raw_line("{not_valid_json")
    inv_req_raw = server.dispatcher.handle_raw_line(json.dumps({"jsonrpc": "1.0", "id": 1}))
    not_found_raw = server.dispatcher.handle_raw_line(
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "nonexistent/method"})
    )
    unknown_tool_raw = server.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "unknown_tool", "arguments": {}},
            }
        )
    )
    domain_err_raw = server.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "fs_read_file", "arguments": {"path": "../etc/passwd"}},
            }
        )
    )

    # 3. ASSERT
    assert parse_err_raw is not None
    assert json.loads(parse_err_raw)["error"]["code"] == JSONRPC_PARSE_ERROR
    assert inv_req_raw is not None
    assert json.loads(inv_req_raw)["error"]["code"] == JSONRPC_INVALID_REQUEST
    assert not_found_raw is not None
    assert json.loads(not_found_raw)["error"]["code"] == JSONRPC_METHOD_NOT_FOUND
    assert unknown_tool_raw is not None
    assert json.loads(unknown_tool_raw)["error"]["code"] == JSONRPC_INVALID_PARAMS

    # Domain security violation MUST return JSON-RPC result with MCP isError=True and RFC 7807 JSON
    assert domain_err_raw is not None
    domain_resp = json.loads(domain_err_raw)
    assert "error" not in domain_resp
    assert domain_resp["result"]["isError"] is True
    rfc7807 = json.loads(domain_resp["result"]["content"][0]["text"])
    assert rfc7807["code"] == "ERR_JAIL_ESCAPE"
    assert rfc7807["status"] == 403

