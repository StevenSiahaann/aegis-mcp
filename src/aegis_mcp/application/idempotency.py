"""In-memory bounded LRU Idempotency Store with SHA-256 payload verification."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Generic, TypeVar

from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.result import Err, Ok, Result

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class _IdempotencyRecord(Generic[T]):
    payload_hash: str
    response: T


class IdempotencyStore(Generic[T]):
    """Thread-safe bounded idempotency registry preventing duplicate mutations."""

    def __init__(self, max_entries: int = 1024) -> None:
        self._max_entries = max(16, max_entries)
        self._store: OrderedDict[str, _IdempotencyRecord[T]] = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def compute_payload_hash(operation: str, payload: dict[str, Any]) -> str:
        """Compute deterministic SHA-256 digest for an operation and its arguments."""
        canonical = json.dumps({"op": operation, "payload": payload}, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def check(self, operation: str, idempotency_key: str, payload_hash: str) -> Result[T | None, DomainError]:
        """Check if an idempotency key has already been processed.

        Returns:
        - Ok(None) if the key is new.
        - Ok(cached_response) if the key exists and payload hash matches.
        - Err(DomainError(ERR_IDEMPOTENCY_MISMATCH)) if the key exists with a different payload.
        """
        scoped_key = f"{operation}:{idempotency_key}"
        with self._lock:
            record = self._store.get(scoped_key)
            if record is None:
                return Ok(None)
            self._store.move_to_end(scoped_key)
            if record.payload_hash != payload_hash:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_IDEMPOTENCY_MISMATCH,
                        title="Idempotency Payload Mismatch",
                        detail=(
                            f"Idempotency key '{idempotency_key}' was already used with a "
                            f"different request payload for operation '{operation}'."
                        ),
                        context={
                            "operation": operation,
                            "idempotency_key": idempotency_key,
                        },
                    )
                )
            return Ok(record.response)

    def store(self, operation: str, idempotency_key: str, payload_hash: str, response: T) -> None:
        """Record a completed idempotent operation result."""
        scoped_key = f"{operation}:{idempotency_key}"
        with self._lock:
            self._store[scoped_key] = _IdempotencyRecord(
                payload_hash=payload_hash,
                response=response,
            )
            self._store.move_to_end(scoped_key)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

