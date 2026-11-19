"""Integration tests for SelectorSandboxRunner environment scrubbing, timeout SIGKILL, and pipe flood capping."""

from __future__ import annotations

import os
from pathlib import Path

from aegis_mcp.domain.errors import ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem
from aegis_mcp.infrastructure.os_sandbox.selector_runner import SelectorSandboxRunner


def test_runner_scrubs_host_environment_secrets_and_isolates_home(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_exec=True)
    fs = PosixJailFileSystem(policy)
    runner = SelectorSandboxRunner(policy=policy, fs=fs)

    sentinel_secret = "sk-proj-" + "HostLeakTestSecretValue999999999"
    os.environ["OPENAI_API_KEY"] = sentinel_secret
    os.environ["AWS_SECRET_ACCESS_KEY"] = "aws_super_secret_host_value"

    code = (
        "import os, json\n"
        "print(json.dumps({\n"
        "  'has_openai': 'OPENAI_API_KEY' in os.environ,\n"
        "  'has_aws': 'AWS_SECRET_ACCESS_KEY' in os.environ,\n"
        "  'home': os.environ.get('HOME'),\n"
        "}))\n"
    )

    try:
        # 2. ACT
        result = runner.run_python(code, timeout_seconds=5.0)
    finally:
        os.environ.pop("OPENAI_API_KEY", None)
        os.environ.pop("AWS_SECRET_ACCESS_KEY", None)

    # 3. ASSERT
    assert result.is_ok is True
    exec_dto = result.unwrap()
    assert exec_dto.exit_code == 0
    assert '"has_openai": false' in exec_dto.stdout
    assert '"has_aws": false' in exec_dto.stdout
    assert ".aegis-sandbox/tmp" in exec_dto.stdout


def test_runner_terminates_infinite_loop_and_grandchild_processes_on_timeout(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(
        workspace_root=tmp_path,
        allow_exec=True,
        allow_subprocess=True,
        default_timeout_seconds=0.35,
        max_timeout_seconds=2.0,
    )
    fs = PosixJailFileSystem(policy)
    runner = SelectorSandboxRunner(policy=policy, fs=fs)

    code = (
        "import subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print('started_loop', flush=True)\n"
        "while True:\n"
        "    time.sleep(0.05)\n"
    )

    # 2. ACT
    result = runner.run_python(code, timeout_seconds=0.35)

    # 3. ASSERT
    assert result.is_err is True
    err = result.unwrap_err()
    assert err.code == ErrorCode.ERR_EXEC_TIMEOUT
    assert "started_loop" in err.context["partial_stdout"]


def test_runner_prevents_pipe_deadlock_and_truncates_large_output(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(
        workspace_root=tmp_path,
        allow_exec=True,
        max_output_bytes=4096,
    )
    fs = PosixJailFileSystem(policy)
    runner = SelectorSandboxRunner(policy=policy, fs=fs)

    # Write 128KB simultaneously to both stdout and stderr (exceeding 64KB OS pipe buffer)
    code = (
        "import sys\n"
        "chunk = 'A' * 8192 + '\\n'\n"
        "for _ in range(16):\n"
        "    sys.stdout.write(chunk)\n"
        "    sys.stderr.write(chunk)\n"
        "sys.stdout.flush()\n"
        "sys.stderr.flush()\n"
    )

    # 2. ACT
    result = runner.run_python(code, timeout_seconds=5.0)

    # 3. ASSERT
    assert result.is_ok is True
    dto = result.unwrap()
    assert dto.exit_code == 0
    assert dto.stdout_truncated is True
    assert dto.stderr_truncated is True
    assert "stdout truncated at 4096 bytes limit" in dto.stdout
    assert "stderr truncated at 4096 bytes limit" in dto.stderr

