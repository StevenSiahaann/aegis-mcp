"""Adversarial regression suite verifying all 9 PoC attack vectors (A-I) and kernel sandbox invariants."""

from __future__ import annotations

import io
import json
import os
import time
from pathlib import Path
from typing import Any

from aegis_mcp.domain.errors import ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.models import JSONRPC_SERVER_NOT_INITIALIZED
from aegis_mcp.infrastructure.mcp_protocol.stdio_server import StdioMCPServer
from aegis_mcp.infrastructure.os_sandbox.kernel_sandbox import BubblewrapDriver, SeatbeltDriver
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem


def _init_and_make_server(policy: SandboxPolicy) -> StdioMCPServer:
    srv = StdioMCPServer(policy=policy, err_stream=io.StringIO())
    srv.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            }
        )
    )
    return srv


def _call_tool(
    server: StdioMCPServer,
    req_id: int,
    name: str,
    args: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    raw = server.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            }
        )
    )
    assert raw is not None
    res = json.loads(raw)["result"]
    return bool(res["isError"]), json.loads(res["content"][0]["text"])


def test_poc_a_and_b_and_c_block_outside_file_reads_via_command_and_python(tmp_path: Path) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    outside = tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    secret = outside / "host_secret.txt"
    secret.write_text("HOST-ONLY-SECRET-CONTENT\n", encoding="utf-8")

    policy = SandboxPolicy(
        workspace_root=ws,
        allow_write=True,
        allow_exec=True,
        default_timeout_seconds=2.0,
    )
    srv = _init_and_make_server(policy)

    # 2. ACT
    err_a, payload_a = _call_tool(
        srv,
        1,
        "exec_command",
        {"binary": "head", "args": [str(secret)]},
    )
    err_b, payload_b = _call_tool(
        srv,
        2,
        "exec_command",
        {"binary": "git", "args": ["diff", "--no-index", str(secret), "/dev/null"]},
    )
    err_c, payload_c = _call_tool(
        srv,
        3,
        "exec_python",
        {"code": f"print(open({str(secret)!r}).read())"},
    )

    # 3. ASSERT
    assert err_a is True
    assert payload_a["code"] == "ERR_JAIL_ESCAPE"
    assert err_b is True
    assert payload_b["code"] == "ERR_JAIL_ESCAPE"
    # In PoC C, kernel Seatbelt denies opening the outside file
    assert "HOST-ONLY-SECRET-CONTENT" not in payload_c.get("stdout", "")
    assert payload_c.get("exit_code", 1) != 0


def test_poc_d_and_e_and_f_prevent_redaction_corruption_envrc_leak_and_path_disclosure(
    tmp_path: Path,
) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    outside = tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    cfg = ws / "settings.py"
    cfg.write_text('DB_PASSWORD = "real-prod-password-123"\nDEBUG = False\n', encoding="utf-8")
    (ws / ".envrc").write_text("export STRIPE_KEY=plainvalue\n", encoding="utf-8")
    os.symlink(outside, ws / "probe")

    policy = SandboxPolicy(
        workspace_root=ws,
        allow_write=True,
        allow_symlinks_within_jail=True,
    )
    srv = _init_and_make_server(policy)

    # 2. ACT
    _, read_dto = _call_tool(srv, 1, "fs_read_file", {"path": "settings.py"})
    modified = read_dto["content"].replace("DEBUG = False", "DEBUG = True")
    err_d, payload_d = _call_tool(
        srv,
        2,
        "fs_write_file",
        {
            "path": "settings.py",
            "content": modified,
            "expected_sha256": read_dto["sha256"],
        },
    )
    err_patch_d, payload_patch_d = _call_tool(
        srv,
        3,
        "fs_patch_file",
        {
            "path": "settings.py",
            "target": "DEBUG = False",
            "replacement": 'DB_PASSWORD = "[REDACTED_SECRET]"\nDEBUG = True',
        },
    )
    err_e, payload_e = _call_tool(srv, 4, "fs_read_file", {"path": ".envrc"})
    err_f, payload_f = _call_tool(srv, 5, "fs_read_file", {"path": "probe/host_secret.txt"})

    # 3. ASSERT
    assert err_d is True
    assert payload_d["code"] == "ERR_REDACTED_CONTENT_WRITE_BLOCKED"
    assert "real-prod-password-123" in cfg.read_text(encoding="utf-8")
    assert err_patch_d is True
    assert payload_patch_d["code"] == "ERR_REDACTED_CONTENT_WRITE_BLOCKED"

    assert err_e is True
    assert payload_e["code"] == "ERR_SENSITIVE_PATH_BLOCKED"

    assert err_f is True
    assert str(outside) not in json.dumps(payload_f)


def test_poc_g_and_h_and_i_block_redos_alternation_setsid_escape_and_uninitialized_call(
    tmp_path: Path,
) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "big.txt").write_text("a" * 30 + "!\n", encoding="utf-8")
    marker = ws / "survivor.txt"

    policy = SandboxPolicy(
        workspace_root=ws,
        allow_write=True,
        allow_exec=True,
        default_timeout_seconds=0.35,
    )
    srv = _init_and_make_server(policy)
    uninit_srv = StdioMCPServer(policy=policy, err_stream=io.StringIO())

    fork_setsid_code = (
        "import os, time\n"
        "if os.fork() == 0:\n"
        "    os.setsid()\n"
        f"    time.sleep(0.6); open({str(marker)!r}, 'w').write('alive'); os._exit(0)\n"
        "time.sleep(10)\n"
    )

    # 2. ACT
    t0 = time.perf_counter()
    err_g, payload_g = _call_tool(
        srv,
        1,
        "fs_search_text",
        {"query": "(a|aa)+$", "is_regex": True, "path": "big.txt"},
    )
    elapsed_g = time.perf_counter() - t0

    _call_tool(
        srv,
        2,
        "exec_python",
        {"code": fork_setsid_code, "timeout_seconds": 0.25},
    )
    time.sleep(0.8)

    uninit_raw = uninit_srv.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 99,
                "method": "tools/call",
                "params": {"name": "sandbox_inspect_policy", "arguments": {}},
            }
        )
    )

    # 3. ASSERT
    assert err_g is True
    assert payload_g["code"] == "ERR_INVALID_REGEX"
    assert elapsed_g < 0.05

    assert marker.exists() is False

    assert uninit_raw is not None
    uninit_resp = json.loads(uninit_raw)
    assert uninit_resp["error"]["code"] == JSONRPC_SERVER_NOT_INITIALIZED


def test_hardlink_blocked_and_kernel_drivers_build_expected_arguments(tmp_path: Path) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    outside = tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    outside_file = outside / "target.txt"
    outside_file.write_text("secret", encoding="utf-8")
    hardlink_inside = ws / "hardlinked.txt"
    os.link(outside_file, hardlink_inside)
    (ws / ".env").write_text("A=1", encoding="utf-8")

    policy = SandboxPolicy(workspace_root=ws, allow_write=True, allow_subprocess=True)
    fs = PosixJailFileSystem(policy)
    sb_driver = SeatbeltDriver(policy=policy, binary="/usr/bin/sandbox-exec")
    bw_driver = BubblewrapDriver(policy=policy, binary="/usr/bin/bwrap")

    # 2. ACT
    read_hl = fs.read_text_file("hardlinked.txt")
    sb_argv = sb_driver.wrap(["python3", "-c", "pass"], cwd=ws)
    bw_argv = bw_driver.wrap(["python3", "-c", "pass"], cwd=ws)

    # 3. ASSERT
    assert read_hl.is_err is True
    assert read_hl.unwrap_err().code == ErrorCode.ERR_SPECIAL_FILE_BLOCKED
    assert sb_argv[0] == "/usr/bin/sandbox-exec"
    assert "(deny default)" in sb_argv[2]
    assert "(allow process-fork)" in sb_argv[2]
    assert "--unshare-all" in bw_argv
    assert "--die-with-parent" in bw_argv
