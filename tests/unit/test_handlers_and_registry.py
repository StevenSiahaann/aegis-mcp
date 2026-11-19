"""Unit tests for all 8 Application Use-Case Handlers, ToolRegistry, CleanEnvironmentBuilder, and CLI parser."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

from aegis_mcp.__main__ import build_arg_parser, main
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.stdio_server import StdioMCPServer
from aegis_mcp.infrastructure.os_sandbox.env_builder import CleanEnvironmentBuilder
from aegis_mcp.infrastructure.os_sandbox.rlimits import (
    build_macos_seatbelt_profile,
    make_preexec_limiter,
)


def _rpc_call(server: StdioMCPServer, req_id: int, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if not server.dispatcher._initialized:
        server.dispatcher.handle_raw_line(
            json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        )
    raw = server.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
            }
        )
    )
    assert raw is not None
    parsed: dict[str, Any] = json.loads(raw)["result"]
    return parsed


def test_registry_and_handlers_full_workflow_with_cas_idempotency_and_wrap(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(
        workspace_root=tmp_path,
        allow_write=True,
        allow_exec=True,
        wrap_untrusted_content=True,
    )
    err_buf = io.StringIO()
    server = StdioMCPServer(policy=policy, err_stream=err_buf)

    # 2. ACT
    write_1 = _rpc_call(
        server,
        1,
        "fs_write_file",
        {
            "path": "module/calc.py",
            "content": "def add(a, b):\n    return a + b\n",
            "idempotency_key": "write-k1",
        },
    )
    write_replay = _rpc_call(
        server,
        2,
        "fs_write_file",
        {
            "path": "module/calc.py",
            "content": "def add(a, b):\n    return a + b\n",
            "idempotency_key": "write-k1",
        },
    )
    write_mismatch = _rpc_call(
        server,
        3,
        "fs_write_file",
        {
            "path": "module/calc.py",
            "content": "different content",
            "idempotency_key": "write-k1",
        },
    )

    write_dto = json.loads(write_1["content"][0]["text"])
    initial_sha = write_dto["new_sha256"]

    patch_1 = _rpc_call(
        server,
        4,
        "fs_patch_file",
        {
            "path": "module/calc.py",
            "target": "return a + b",
            "replacement": "return int(a) + int(b)",
            "expected_sha256": initial_sha,
            "idempotency_key": "patch-k1",
        },
    )
    patch_replay = _rpc_call(
        server,
        5,
        "fs_patch_file",
        {
            "path": "module/calc.py",
            "target": "return a + b",
            "replacement": "return int(a) + int(b)",
            "expected_sha256": initial_sha,
            "idempotency_key": "patch-k1",
        },
    )

    read_res = _rpc_call(
        server,
        6,
        "fs_read_file",
        {"path": "module/calc.py", "start_line": 1, "end_line": 2, "max_bytes": 4096},
    )
    list_res = _rpc_call(
        server,
        7,
        "fs_list_directory",
        {"path": ".", "max_depth": 3, "include_hidden": False},
    )
    search_res = _rpc_call(
        server,
        8,
        "fs_search_text",
        {"query": "int(a)", "path": ".", "is_regex": False, "max_results": 10},
    )
    py_res = _rpc_call(
        server,
        9,
        "exec_python",
        {"code": "from module.calc import add\nprint(add(19, 23))"},
    )
    cmd_res = _rpc_call(
        server,
        10,
        "exec_command",
        {"binary": "ls", "args": ["module"], "cwd": "."},
    )
    inspect_res = _rpc_call(server, 11, "sandbox_inspect_policy", {})

    # 3. ASSERT
    assert write_1["isError"] is False
    assert write_dto["idempotent_replayed"] is False
    assert json.loads(write_replay["content"][0]["text"])["idempotent_replayed"] is True
    assert write_mismatch["isError"] is True
    assert json.loads(write_mismatch["content"][0]["text"])["code"] == "ERR_IDEMPOTENCY_MISMATCH"

    assert patch_1["isError"] is False
    assert json.loads(patch_replay["content"][0]["text"])["idempotent_replayed"] is True

    read_dto = json.loads(read_res["content"][0]["text"])
    assert "<untrusted_file_content" in read_dto["content"]
    assert "return int(a) + int(b)" in read_dto["content"]

    list_dto = json.loads(list_res["content"][0]["text"])
    assert any(e["relative_path"] == "module/calc.py" for e in list_dto["entries"])

    search_dto = json.loads(search_res["content"][0]["text"])
    assert len(search_dto["matches"]) == 1

    py_dto = json.loads(py_res["content"][0]["text"])
    assert py_dto["stdout"].strip() == "42"

    cmd_dto = json.loads(cmd_res["content"][0]["text"])
    assert "calc.py" in cmd_dto["stdout"]

    inspect_dto = json.loads(inspect_res["content"][0]["text"])
    assert inspect_dto["telemetry"]["total_requests"] == 10


def test_readonly_and_disabled_exec_policies_and_validation_errors(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_write=False, allow_exec=False)
    server = StdioMCPServer(policy=policy, err_stream=io.StringIO())
    (tmp_path / "sample.txt").write_text("alpha\nbeta\nalpha\n", encoding="utf-8")

    # 2. ACT
    ro_write = _rpc_call(server, 1, "fs_write_file", {"path": "x.txt", "content": "hi"})
    ro_patch = _rpc_call(
        server,
        2,
        "fs_patch_file",
        {"path": "sample.txt", "target": "alpha", "replacement": "gamma"},
    )
    dis_py = _rpc_call(server, 3, "exec_python", {"code": "print(1)"})
    dis_cmd = _rpc_call(server, 4, "exec_command", {"binary": "ls"})
    bad_range = _rpc_call(
        server,
        5,
        "fs_read_file",
        {"path": "sample.txt", "start_line": 5, "end_line": 2},
    )
    pydantic_err = _rpc_call(
        server,
        6,
        "fs_read_file",
        {"path": "sample.txt", "unexpected_field": 123},
    )
    ping_raw = server.dispatcher.handle_raw_line(
        json.dumps({"jsonrpc": "2.0", "id": 7, "method": "ping"})
    )
    res_list_raw = server.dispatcher.handle_raw_line(
        json.dumps({"jsonrpc": "2.0", "id": 8, "method": "resources/list"})
    )
    prompts_list_raw = server.dispatcher.handle_raw_line(
        json.dumps({"jsonrpc": "2.0", "id": 9, "method": "prompts/list"})
    )

    # 3. ASSERT
    assert json.loads(ro_write["content"][0]["text"])["code"] == "ERR_READ_ONLY_MODE"
    assert json.loads(ro_patch["content"][0]["text"])["code"] == "ERR_READ_ONLY_MODE"
    assert json.loads(dis_py["content"][0]["text"])["code"] == "ERR_EXEC_DISABLED"
    assert json.loads(dis_cmd["content"][0]["text"])["code"] == "ERR_EXEC_DISABLED"
    assert json.loads(bad_range["content"][0]["text"])["code"] == "ERR_VALIDATION_FAILED"
    assert json.loads(pydantic_err["content"][0]["text"])["code"] == "ERR_VALIDATION_FAILED"
    assert ping_raw is not None
    assert json.loads(ping_raw)["result"] == {}
    assert res_list_raw is not None
    assert json.loads(res_list_raw)["result"] == {"resources": []}
    assert prompts_list_raw is not None
    assert json.loads(prompts_list_raw)["result"] == {"prompts": []}


def test_stdio_server_serve_forever_loop_and_telemetry(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path)
    in_stream = io.StringIO(
        json.dumps({"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-03-26"}})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 99}})
        + "\n\n"
    )
    out_stream = io.StringIO()
    err_stream = io.StringIO()
    server = StdioMCPServer(
        policy=policy,
        in_stream=in_stream,
        out_stream=out_stream,
        err_stream=err_stream,
    )

    # 2. ACT
    server.serve_forever()
    out_lines = [line for line in out_stream.getvalue().splitlines() if line.strip()]

    # 3. ASSERT
    assert len(out_lines) == 3
    assert server.telemetry.snapshot()["total_requests"] == 0


def test_clean_env_builder_and_rlimits_and_cli_parser(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_write=True)
    extra = {
        "SAFE_CUSTOM_FLAG": "enabled",
        "SECRET_API_KEY": "should_be_dropped",
        "SNEAKY_VAR": "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD",
    }

    # 2. ACT
    env = CleanEnvironmentBuilder.build(policy, extra_env=extra)
    sb_profile = build_macos_seatbelt_profile(tmp_path, allow_write=True)
    limiter_fn = make_preexec_limiter(cpu_seconds=5, fsize_bytes=1048576, nofile=64)
    parser = build_arg_parser()
    parsed_args = parser.parse_args(["--root", str(tmp_path), "--allow-write", "--allow-exec"])

    # 3. ASSERT
    assert env["SAFE_CUSTOM_FLAG"] == "enabled"
    assert "SECRET_API_KEY" not in env
    assert "SNEAKY_VAR" not in env
    assert "(deny network*)" in sb_profile
    assert callable(limiter_fn)
    assert parsed_args.allow_write is True
    assert parsed_args.allow_exec is True

    # Verify CLI main() rejects nonexistent workspace root cleanly with exit code 2
    rc_bad = main(["--root", str(tmp_path / "nonexistent_dir"), "--allowed-binaries", "git,ls"])
    assert rc_bad == 2
