"""Unit tests for IdempotencyStore replay and payload mismatch detection."""

from __future__ import annotations

from aegis_mcp.application.idempotency import IdempotencyStore
from aegis_mcp.domain.errors import ErrorCode


def test_idempotency_store_replay_and_payload_mismatch() -> None:
    # 1. ARRANGE
    store: IdempotencyStore[dict[str, str]] = IdempotencyStore(max_entries=16)
    key = "idemp-key-001"
    hash_a = store.compute_payload_hash("fs_write_file", {"path": "a.txt", "content": "v1"})
    hash_b = store.compute_payload_hash("fs_write_file", {"path": "a.txt", "content": "v2"})

    # 2. ACT
    first_check = store.check("fs_write_file", key, hash_a)
    store.store("fs_write_file", key, hash_a, {"status": "written"})
    replay_check = store.check("fs_write_file", key, hash_a)
    mismatch_check = store.check("fs_write_file", key, hash_b)

    # 3. ASSERT
    assert first_check.is_ok is True
    assert first_check.unwrap() is None
    assert replay_check.is_ok is True
    assert replay_check.unwrap() == {"status": "written"}
    assert mismatch_check.is_err is True
    assert mismatch_check.unwrap_err().code == ErrorCode.ERR_IDEMPOTENCY_MISMATCH

