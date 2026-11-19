"""Use-case handler for atomic file writing with Optimistic Concurrency (SHA-256 CAS) and Idempotency."""

from __future__ import annotations

from dataclasses import replace

from aegis_mcp.application.idempotency import IdempotencyStore
from aegis_mcp.application.ports import FileSystemPort, FileWriteResult
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result


class WriteFileHandler:
    """Executes atomic file write operations guarded by read-only policy, CAS, and idempotency."""

    def __init__(
        self,
        fs: FileSystemPort,
        policy: SandboxPolicy,
        idempotency_store: IdempotencyStore[FileWriteResult],
    ) -> None:
        self._fs = fs
        self._policy = policy
        self._idempotency = idempotency_store

    def execute(
        self,
        path: str,
        content: str,
        *,
        expected_sha256: str | None = None,
        idempotency_key: str | None = None,
    ) -> Result[FileWriteResult, DomainError]:
        if not self._policy.allow_write:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_READ_ONLY_MODE,
                    title="Sandbox Read-Only Mode Enforced",
                    detail=(
                        "File mutation is disabled because the server is running in read-only mode "
                        "(Least Privilege default). Launch with '--allow-write' to enable mutations."
                    ),
                    is_security_violation=True,
                    context={"path": path},
                )
            )

        encoded_len = len(content.encode("utf-8"))
        if encoded_len > self._policy.max_write_bytes:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_FILE_TOO_LARGE,
                    title="Write Payload Exceeds Policy Limit",
                    detail=(
                        f"Content size ({encoded_len} bytes) exceeds maximum allowed write size "
                        f"({self._policy.max_write_bytes} bytes)."
                    ),
                    context={
                        "bytes": encoded_len,
                        "max_write_bytes": self._policy.max_write_bytes,
                    },
                )
            )

        payload_hash = ""
        if idempotency_key:
            payload_hash = self._idempotency.compute_payload_hash(
                "fs_write_file",
                {
                    "path": path,
                    "content": content,
                    "expected_sha256": expected_sha256,
                },
            )
            cached_check = self._idempotency.check("fs_write_file", idempotency_key, payload_hash)
            if cached_check.is_err:
                return Err(cached_check.unwrap_err())
            cached_val = cached_check.unwrap()
            if cached_val is not None:
                return Ok(replace(cached_val, idempotent_replayed=True))

        write_res = self._fs.write_text_file(
            path,
            content,
            expected_sha256=expected_sha256,
        )
        if write_res.is_ok and idempotency_key:
            self._idempotency.store(
                "fs_write_file",
                idempotency_key,
                payload_hash,
                write_res.unwrap(),
            )
        return write_res

