"""Unit tests for CommandArgumentGuard allowlist and git subcommand/flag protections."""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis_mcp.domain.errors import ErrorCode
from aegis_mcp.domain.matchers import CommandArgumentGuard
from aegis_mcp.domain.policy import SandboxPolicy


def test_command_guard_allows_safe_allowlisted_commands(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_exec=True)

    # 2. ACT
    res_git = CommandArgumentGuard.validate("git", ["status", "--short"], policy)
    res_pytest = CommandArgumentGuard.validate("pytest", ["-q", "tests/unit"], policy)

    # 3. ASSERT
    assert res_git.is_ok is True
    assert res_git.unwrap() == ("git", ["status", "--short"])
    assert res_pytest.is_ok is True


@pytest.mark.parametrize(
    ("binary", "args", "expected_code"),
    [
        ("bash", ["-c", "whoami"], ErrorCode.ERR_COMMAND_NOT_ALLOWED),
        ("curl", ["https://evil.example.com"], ErrorCode.ERR_COMMAND_NOT_ALLOWED),
        ("/usr/bin/git", ["status"], ErrorCode.ERR_COMMAND_NOT_ALLOWED),
        ("../bin/pytest", [], ErrorCode.ERR_COMMAND_NOT_ALLOWED),
        ("git\x00", ["status"], ErrorCode.ERR_COMMAND_NOT_ALLOWED),
        ("git", ["status\x00"], ErrorCode.ERR_DANGEROUS_ARGUMENTS),
        ("git", ["push", "origin", "main"], ErrorCode.ERR_DANGEROUS_ARGUMENTS),
        ("git", ["remote", "add", "evil", "https://example.com"], ErrorCode.ERR_DANGEROUS_ARGUMENTS),
        ("git", ["config", "--global", "user.name", "x"], ErrorCode.ERR_DANGEROUS_ARGUMENTS),
        ("git", ["-c", "core.sshCommand=sh", "status"], ErrorCode.ERR_DANGEROUS_ARGUMENTS),
    ],
)
def test_command_guard_blocks_unlisted_binaries_and_dangerous_git_args(
    tmp_path: Path,
    binary: str,
    args: list[str],
    expected_code: ErrorCode,
) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_exec=True)

    # 2. ACT
    result = CommandArgumentGuard.validate(binary, args, policy)

    # 3. ASSERT
    assert result.is_err is True
    err = result.unwrap_err()
    assert err.code == expected_code
    assert err.is_security_violation is True

