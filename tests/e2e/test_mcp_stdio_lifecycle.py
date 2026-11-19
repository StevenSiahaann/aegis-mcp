"""End-to-End black-box test spawning `python -m aegis_mcp` over real stdio pipes."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


def _rpc_exchange(proc: subprocess.Popen[str], request: dict[str, Any]) -> dict[str, Any]:
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(json.dumps(request) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    assert line, "Expected JSON-RPC response line from server stdout"
    parsed: dict[str, Any] = json.loads(line)
    return parsed


def test_e2e_stdio_server_full_lifecycle_and_audit_log(tmp_path: Path) -> None:
    # 1. ARRANGE
    workspace = tmp_path / "project"
    workspace.mkdir()
    (workspace / ".env").write_text("DB_PASS=top_secret_value", encoding="utf-8")
    (workspace / "hello.txt").write_text("line1\nline2\n", encoding="utf-8")
    audit_file = tmp_path / "audit.ndjson"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegis_mcp",
            "--root",
            str(workspace),
            "--allow-write",
            "--allow-exec",
            "--audit-log",
            str(audit_file),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        # 2. ACT
        init_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            },
        )
        assert proc.stdin is not None
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()

        read_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "fs_read_file", "arguments": {"path": "hello.txt"}},
            },
        )

        # Attack 1: Attempt to read .env
        env_attack_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "fs_read_file", "arguments": {"path": ".env"}},
            },
        )

        # Attack 2: Attempt shell injection via unlisted binary
        cmd_attack_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "exec_command",
                    "arguments": {"binary": "sh", "args": ["-c", "cat /etc/passwd"]},
                },
            },
        )

        # Valid Python execution
        py_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "exec_python",
                    "arguments": {"code": "print(21 * 2)"},
                },
            },
        )

        # Inspect policy & telemetry
        inspect_resp = _rpc_exchange(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "sandbox_inspect_policy", "arguments": {}},
            },
        )
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5.0)
        if proc.stderr:
            proc.stderr.close()
        if proc.stdout:
            proc.stdout.close()

    # 3. ASSERT
    assert init_resp["result"]["serverInfo"]["name"] == "aegis-mcp"

    assert read_resp["result"]["isError"] is False
    read_data = json.loads(read_resp["result"]["content"][0]["text"])
    assert "line1" in read_data["content"]

    assert env_attack_resp["result"]["isError"] is True
    env_err = json.loads(env_attack_resp["result"]["content"][0]["text"])
    assert env_err["code"] == "ERR_SENSITIVE_PATH_BLOCKED"

    assert cmd_attack_resp["result"]["isError"] is True
    cmd_err = json.loads(cmd_attack_resp["result"]["content"][0]["text"])
    assert cmd_err["code"] == "ERR_COMMAND_NOT_ALLOWED"

    assert py_resp["result"]["isError"] is False
    py_data = json.loads(py_resp["result"]["content"][0]["text"])
    assert py_data["stdout"].strip() == "42"

    inspect_data = json.loads(inspect_resp["result"]["content"][0]["text"])
    assert inspect_data["telemetry"]["security_violations_blocked"] == 2
    assert audit_file.exists()
    audit_lines = [json.loads(line) for line in audit_file.read_text(encoding="utf-8").splitlines()]
    assert any(entry["action"] == "SANDBOX_VIOLATION_BLOCKED" for entry in audit_lines)

