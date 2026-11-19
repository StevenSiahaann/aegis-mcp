"""Interactive security benchmark simulating 8 real-world AI agent attack vectors against aegis-mcp."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.stdio_server import StdioMCPServer


def _call_tool(server: StdioMCPServer, req_id: int, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    raw = server.dispatcher.handle_raw_line(
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
    )
    assert raw is not None
    resp = json.loads(raw)
    result: dict[str, Any] = resp["result"]
    return result


def run_simulation() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp).resolve()
        workspace = root / "workspace"
        outside = root / "outside_host"
        workspace.mkdir()
        outside.mkdir()

        (outside / "etc_passwd_mock").write_text("root:x:0:0:root:/root:/bin/bash\n", encoding="utf-8")
        (workspace / ".env").write_text("STRIPE_SECRET_KEY=sk-live-999999999999999999999999\n", encoding="utf-8")
        (workspace / "app.py").write_text("def greet():\n    return 'hello'\n", encoding="utf-8")

        # Attack setup: intermediate symlink directory pointing outside the workspace
        os.symlink(outside, workspace / "escaped_dir")
        # Attack setup: named pipe FIFO that would hang a naive open().read() forever
        os.mkfifo(workspace / "hang_pipe.fifo")

        # Inject a fake host API key into the current process environment
        os.environ["OPENAI_API_KEY"] = "sk-proj-" + "HostEnvironmentSecretKey1234567890"

        err_log = io.StringIO()
        policy = SandboxPolicy(
            workspace_root=workspace,
            allow_write=True,
            allow_exec=True,
            default_timeout_seconds=0.4,
            max_timeout_seconds=2.0,
        )
        server = StdioMCPServer(policy=policy, err_stream=err_log)

        scenarios: list[tuple[str, str, dict[str, Any]]] = [
            (
                "1. Path Traversal Escape (../../)",
                "fs_read_file",
                {"path": "../../etc/passwd"},
            ),
            (
                "2. Intermediate Directory Symlink Escape",
                "fs_read_file",
                {"path": "escaped_dir/etc_passwd_mock"},
            ),
            (
                "3. Special Device / FIFO Hang Attack",
                "fs_read_file",
                {"path": "hang_pipe.fifo"},
            ),
            (
                "4. Silent Credential Exfiltration (.env)",
                "fs_read_file",
                {"path": ".env"},
            ),
            (
                "5. Subprocess Host Environment Theft ($OPENAI_API_KEY)",
                "exec_python",
                {"code": "import os; print('LEAKED:', os.environ.get('OPENAI_API_KEY'))"},
            ),
            (
                "6. Arbitrary Shell Command Injection",
                "exec_command",
                {"binary": "bash", "args": ["-c", "cat /etc/passwd"]},
            ),
            (
                "7. Dangerous Git Remote Mutation (git push --force)",
                "exec_command",
                {"binary": "git", "args": ["push", "--force", "origin", "main"]},
            ),
            (
                "8. Infinite Loop & Grandchild Process Fork Hang",
                "exec_python",
                {"code": "import time\nwhile True:\n    time.sleep(0.05)", "timeout_seconds": 0.35},
            ),
        ]

        sys.stdout.write("=" * 78 + "\n")
        sys.stdout.write("  AEGIS-MCP: 8-VECTOR ADVERSARIAL SECURITY BENCHMARK\n")
        sys.stdout.write("=" * 78 + "\n")

        for idx, (title, tool_name, args) in enumerate(scenarios, start=1):
            res = _call_tool(server, idx, tool_name, args)
            payload = json.loads(res["content"][0]["text"])
            is_err = res["isError"]
            if is_err:
                status_badge = f"BLOCKED [{payload.get('code')}] (HTTP {payload.get('status')})"
                detail = payload.get("detail", "")
            else:
                # Scenario 5 succeeds as a process but prints 'LEAKED: None' because env was scrubbed
                stdout_val = payload.get("stdout", "").strip()
                status_badge = f"SCRUBBED [exit={payload.get('exit_code')}]"
                detail = f"Subprocess output: {stdout_val}"

            sys.stdout.write(f"\n{title}\n")
            sys.stdout.write(f"  -> Outcome : {status_badge}\n")
            sys.stdout.write(f"  -> Detail  : {detail}\n")

        policy_snap = _call_tool(server, 99, "sandbox_inspect_policy", {})
        telemetry = json.loads(policy_snap["content"][0]["text"])["telemetry"]
        sys.stdout.write("\n" + "=" * 78 + "\n")
        sys.stdout.write(
            f"  SUMMARY: {telemetry['total_requests']} requests | "
            f"{telemetry['security_violations_blocked']} security violations blocked | "
            f"p50={telemetry['latency_ms']['p50']}ms, p95={telemetry['latency_ms']['p95']}ms\n"
        )
        sys.stdout.write("=" * 78 + "\n")


if __name__ == "__main__":
    run_simulation()

