"""Unit tests for Result[T, E] monad, SandboxPolicy validation, and RFC 7807 Problem Details serialization."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok


def test_ok_monad_unwrap_and_map() -> None:
    # 1. ARRANGE
    initial: Ok[int] = Ok(21)

    # 2. ACT
    mapped = initial.map(lambda x: x * 2)

    # 3. ASSERT
    assert initial.is_ok is True
    assert initial.is_err is False
    assert mapped.unwrap() == 42
    with pytest.raises(RuntimeError):
        initial.unwrap_err()


def test_err_monad_unwrap_and_map() -> None:
    # 1. ARRANGE
    failure: Err[str] = Err("boundary_violation")

    # 2. ACT
    mapped = failure.map(lambda x: x)

    # 3. ASSERT
    assert failure.is_ok is False
    assert failure.is_err is True
    assert mapped.unwrap_err() == "boundary_violation"
    with pytest.raises(RuntimeError):
        failure.unwrap()


def test_domain_error_rfc7807_serialization() -> None:
    # 1. ARRANGE
    err = DomainError(
        code=ErrorCode.ERR_JAIL_ESCAPE,
        title="Sandbox Boundary Violation",
        detail="Path '/etc/passwd' escapes workspace root.",
        is_security_violation=True,
        context={"requested_path": "../etc/passwd"},
    )
    trace_id = "019344a1b2c37d8e9f00112233445566"

    # 2. ACT
    json_str = err.to_json(trace_id=trace_id, timestamp="2026-11-19T04:00:00.000Z")
    parsed = json.loads(json_str)

    # 3. ASSERT
    assert parsed["type"] == "urn:aegis-mcp:error:jail-escape"
    assert parsed["title"] == "Sandbox Boundary Violation"
    assert parsed["status"] == 403
    assert parsed["code"] == "ERR_JAIL_ESCAPE"
    assert parsed["trace_id"] == trace_id
    assert parsed["timestamp"] == "2026-11-19T04:00:00.000Z"
    assert parsed["context"] == {"requested_path": "../etc/passwd"}


def test_sandbox_policy_validates_bounds(tmp_path: Path) -> None:
    # 1. ARRANGE
    missing_dir = tmp_path / "does_not_exist"
    file_node = tmp_path / "some_file.txt"
    file_node.write_text("hello", encoding="utf-8")

    # 2. ACT & 3. ASSERT
    with pytest.raises(ValueError, match="does not exist"):
        SandboxPolicy(workspace_root=missing_dir)

    with pytest.raises(ValueError, match="not a directory"):
        SandboxPolicy(workspace_root=file_node)

    with pytest.raises(ValueError, match="max_read_bytes"):
        SandboxPolicy(workspace_root=tmp_path, max_read_bytes=0)

    with pytest.raises(ValueError, match="max_write_bytes"):
        SandboxPolicy(workspace_root=tmp_path, max_write_bytes=0)

    with pytest.raises(ValueError, match="max_output_bytes"):
        SandboxPolicy(workspace_root=tmp_path, max_output_bytes=0)

    with pytest.raises(ValueError, match="max_timeout_seconds"):
        SandboxPolicy(workspace_root=tmp_path, max_timeout_seconds=0.0)

    with pytest.raises(ValueError, match="default_timeout_seconds"):
        SandboxPolicy(
            workspace_root=tmp_path,
            max_timeout_seconds=5.0,
            default_timeout_seconds=10.0,
        )

    with pytest.raises(ValueError, match="max_dir_depth"):
        SandboxPolicy(workspace_root=tmp_path, max_dir_depth=0)


def test_sandbox_policy_clamp_timeout(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(
        workspace_root=tmp_path,
        default_timeout_seconds=4.0,
        max_timeout_seconds=12.0,
    )

    # 2. ACT
    default_t = policy.clamp_timeout(None)
    negative_t = policy.clamp_timeout(-3.0)
    within_t = policy.clamp_timeout(7.5)
    capped_t = policy.clamp_timeout(99.0)

    # 3. ASSERT
    assert default_t == 4.0
    assert negative_t == 4.0
    assert within_t == 7.5
    assert capped_t == 12.0

