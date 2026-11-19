"""Use-case handler for atomic exact-block file patching with SHA-256 CAS and Idempotency."""

from __future__ import annotations

from dataclasses import replace

from aegis_mcp.application.idempotency import IdempotencyStore
from aegis_mcp.application.ports import FilePatchResult, FileSystemPort
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result


class PatchFileHandler:
    """Executes atomic target->replacement block patching guarded by CAS and idempotency."""

    def __init__(
        self,
        fs: FileSystemPort,
        policy: SandboxPolicy,
        idempotency_store: IdempotencyStore[FilePatchResult],
    ) -> None:
        self._fs = fs
        self._policy = policy
        self._idempotency = idempotency_store

    def execute(
        self,
        path: str,
        target: str,
        replacement: str,
        *,
        expected_sha256: str | None = None,
        idempotency_key: str | None = None,
    ) -> Result[FilePatchResult, DomainError]:
        if not self._policy.allow_write:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_READ_ONLY_MODE,
                    title="Sandbox Read-Only Mode Enforced",
                    detail=(
                        "File patching is disabled because the server is running in read-only mode "
                        "(Least Privilege default). Launch with '--allow-write' to enable mutations."
                    ),
                    is_security_violation=True,
                    context={"path": path},
                )
            )

        if not target:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Empty Patch Target",
                    detail="Target block to replace must not be empty.",
                )
            )

        payload_hash = ""
        if idempotency_key:
            payload_hash = self._idempotency.compute_payload_hash(
                "fs_patch_file",
                {
                    "path": path,
                    "target": target,
                    "replacement": replacement,
                    "expected_sha256": expected_sha256,
                },
            )
            cached_check = self._idempotency.check("fs_patch_file", idempotency_key, payload_hash)
            if cached_check.is_err:
                return Err(cached_check.unwrap_err())
            cached_val = cached_check.unwrap()
            if cached_val is not None:
                return Ok(replace(cached_val, idempotent_replayed=True))

        patch_res = self._fs.patch_text_file(
            path,
            target,
            replacement,
            expected_sha256=expected_sha256,
        )
        if patch_res.is_ok and idempotency_key:
            self._idempotency.store(
                "fs_patch_file",
                idempotency_key,
                payload_hash,
                patch_res.unwrap(),
            )
        return patch_res

