"""Adversarial regression suite verifying all 9 PoC attack vectors (A-I) and kernel sandbox invariants."""

from __future__ import annotations

import io
import json
import os
import threading
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


def test_round2_regressions_attached_flags_symlink_args_kernel_env_write_uri_jwt_redos_streaming(
    tmp_path: Path,
) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    outside = tmp_path / "outside"
    ws.mkdir()
    outside.mkdir()
    (ws / ".env").write_text("INTERNAL_ENV_SECRET=12345\n", encoding="utf-8")
    os.symlink(ws / ".env", ws / "alias.txt")
    (ws / "db.py").write_text(
        'DATABASE_URL = "postgresql://admin:SuperSecretDbPass99@db.internal:5432/prod"\n'
        'JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"\n',
        encoding="utf-8",
    )
    (ws / "huge.log").write_text("log line content\n" * 180_000 + "final_tail", encoding="utf-8")

    policy = SandboxPolicy(workspace_root=ws, allow_write=True, allow_exec=True)
    srv = _init_and_make_server(policy)

    # 2. ACT
    err_r1, p_r1 = _call_tool(srv, 1, "exec_command", {"binary": "git", "args": [f"-C{outside}", "status"]})
    err_r2, p_r2 = _call_tool(srv, 2, "exec_command", {"binary": "head", "args": ["alias.txt"]})
    _call_tool(srv, 3, "exec_python", {"code": "open('.env', 'w').write('PWN=1')"})
    err_r4, p_r4 = _call_tool(srv, 4, "fs_read_file", {"path": "db.py"})
    err_r5, p_r5 = _call_tool(
        srv,
        5,
        "fs_search_text",
        {"query": "a+a+a+a+!$", "is_regex": True, "path": "db.py"},
    )
    err_r6, p_r6 = _call_tool(
        srv,
        6,
        "fs_read_file",
        {"path": "huge.log", "start_line": 1, "end_line": 5},
    )
    err_r6_tail, p_r6_tail = _call_tool(
        srv,
        7,
        "fs_read_file",
        {"path": "huge.log", "start_line": 180_000, "end_line": 180_001},
    )

    # 3. ASSERT
    assert err_r1 is True
    assert p_r1["code"] in ("ERR_JAIL_ESCAPE", "ERR_DANGEROUS_ARGUMENTS")
    assert err_r2 is True
    assert p_r2["code"] == "ERR_SYMLINK_BLOCKED"
    assert (ws / ".env").read_text(encoding="utf-8") == "INTERNAL_ENV_SECRET=12345\n"
    assert err_r4 is False
    assert "[REDACTED_URI_PASSWORD]" in p_r4["content"]
    assert "[REDACTED_JWT_TOKEN]" in p_r4["content"]
    assert "SuperSecretDbPass99" not in p_r4["content"]
    assert err_r5 is True
    assert p_r5["code"] == "ERR_INVALID_REGEX"
    assert err_r6 is False
    assert p_r6["start_line"] == 1
    assert p_r6["end_line"] == 5
    assert p_r6["total_lines"] == 180_001
    assert err_r6_tail is False
    assert "final_tail" in p_r6_tail["content"]


def test_in_flight_cancellation_extra_read_paths_and_re2_engine(tmp_path: Path) -> None:
    # 1. ARRANGE
    ws = tmp_path / "ws"
    shared_ro = tmp_path / "shared_ro"
    secret_dir = tmp_path / "secret_dir"
    ws.mkdir()
    shared_ro.mkdir()
    secret_dir.mkdir()
    (shared_ro / "lib_data.txt").write_text("SHARED_LIBRARY_CONTENT_OK\n", encoding="utf-8")
    (secret_dir / "forbidden.txt").write_text("FORBIDDEN_OUTSIDE\n", encoding="utf-8")
    (ws / "code.py").write_text("def handler_v1():\n    return 123\n", encoding="utf-8")

    policy = SandboxPolicy(
        workspace_root=ws,
        allow_write=True,
        allow_exec=True,
        default_timeout_seconds=10.0,
        extra_read_paths=(shared_ro,),
    )
    srv = _init_and_make_server(policy)

    cancel_result_holder: list[tuple[bool, dict[str, Any]]] = []

    def _run_long_task() -> None:
        res = _call_tool(
            srv,
            777,
            "exec_python",
            {"code": "import time\nprint('started_777', flush=True)\ntime.sleep(10)", "timeout_seconds": 10.0},
        )
        cancel_result_holder.append(res)

    worker = threading.Thread(target=_run_long_task)

    # 2. ACT
    t0 = time.perf_counter()
    worker.start()
    time.sleep(0.2)
    srv.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 777},
            }
        )
    )
    worker.join(timeout=3.0)
    cancel_elapsed = time.perf_counter() - t0

    # Extra read path allowed for read, denied for write, and sibling secret_dir still denied
    err_ro_read, p_ro_read = _call_tool(
        srv,
        801,
        "exec_python",
        {"code": f"print(open({str(shared_ro / 'lib_data.txt')!r}).read().strip())"},
    )
    _, p_ro_write = _call_tool(
        srv,
        802,
        "exec_python",
        {"code": f"open({str(shared_ro / 'hack.txt')!r}, 'w').write('x')"},
    )
    _, p_sec_read = _call_tool(
        srv,
        803,
        "exec_python",
        {"code": f"print(open({str(secret_dir / 'forbidden.txt')!r}).read())"},
    )
    err_re2, p_re2 = _call_tool(
        srv,
        804,
        "fs_search_text",
        {"query": r"def\s+handler_v[0-9]+", "is_regex": True, "path": "code.py"},
    )

    # 3. ASSERT
    assert len(cancel_result_holder) == 1
    c_err, c_payload = cancel_result_holder[0]
    assert c_err is True
    assert c_payload["code"] == "ERR_EXEC_TIMEOUT"
    assert c_payload["context"]["cancelled"] is True
    assert cancel_elapsed < 2.0

    assert err_ro_read is False
    assert p_ro_read["stdout"].strip() == "SHARED_LIBRARY_CONTENT_OK"
    assert p_ro_write["exit_code"] != 0
    assert (shared_ro / "hack.txt").exists() is False
    assert p_sec_read["exit_code"] != 0
    assert "FORBIDDEN_OUTSIDE" not in p_sec_read.get("stdout", "")

    assert err_re2 is False
    assert len(p_re2["matches"]) == 1

