"""Typed domain errors and RFC 7807 Problem Details serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    """Canonical error taxonomy for sandbox security and tool domain failures."""

    ERR_JAIL_ESCAPE = "ERR_JAIL_ESCAPE"
    ERR_SYMLINK_BLOCKED = "ERR_SYMLINK_BLOCKED"
    ERR_SPECIAL_FILE_BLOCKED = "ERR_SPECIAL_FILE_BLOCKED"
    ERR_SENSITIVE_PATH_BLOCKED = "ERR_SENSITIVE_PATH_BLOCKED"
    ERR_READ_ONLY_MODE = "ERR_READ_ONLY_MODE"
    ERR_EXEC_DISABLED = "ERR_EXEC_DISABLED"
    ERR_CAS_CONFLICT = "ERR_CAS_CONFLICT"
    ERR_IDEMPOTENCY_MISMATCH = "ERR_IDEMPOTENCY_MISMATCH"
    ERR_PATCH_TARGET_NOT_FOUND = "ERR_PATCH_TARGET_NOT_FOUND"
    ERR_PATCH_AMBIGUOUS = "ERR_PATCH_AMBIGUOUS"
    ERR_FILE_NOT_FOUND = "ERR_FILE_NOT_FOUND"
    ERR_NOT_A_DIRECTORY = "ERR_NOT_A_DIRECTORY"
    ERR_IS_A_DIRECTORY = "ERR_IS_A_DIRECTORY"
    ERR_FILE_TOO_LARGE = "ERR_FILE_TOO_LARGE"
    ERR_BINARY_FILE = "ERR_BINARY_FILE"
    ERR_COMMAND_NOT_ALLOWED = "ERR_COMMAND_NOT_ALLOWED"
    ERR_DANGEROUS_ARGUMENTS = "ERR_DANGEROUS_ARGUMENTS"
    ERR_EXEC_TIMEOUT = "ERR_EXEC_TIMEOUT"
    ERR_EXEC_FAILED = "ERR_EXEC_FAILED"
    ERR_INVALID_REGEX = "ERR_INVALID_REGEX"
    ERR_VALIDATION_FAILED = "ERR_VALIDATION_FAILED"


_STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.ERR_JAIL_ESCAPE: 403,
    ErrorCode.ERR_SYMLINK_BLOCKED: 403,
    ErrorCode.ERR_SPECIAL_FILE_BLOCKED: 403,
    ErrorCode.ERR_SENSITIVE_PATH_BLOCKED: 403,
    ErrorCode.ERR_READ_ONLY_MODE: 403,
    ErrorCode.ERR_EXEC_DISABLED: 403,
    ErrorCode.ERR_COMMAND_NOT_ALLOWED: 403,
    ErrorCode.ERR_DANGEROUS_ARGUMENTS: 403,
    ErrorCode.ERR_FILE_NOT_FOUND: 404,
    ErrorCode.ERR_CAS_CONFLICT: 409,
    ErrorCode.ERR_FILE_TOO_LARGE: 413,
    ErrorCode.ERR_NOT_A_DIRECTORY: 422,
    ErrorCode.ERR_IS_A_DIRECTORY: 422,
    ErrorCode.ERR_BINARY_FILE: 422,
    ErrorCode.ERR_IDEMPOTENCY_MISMATCH: 422,
    ErrorCode.ERR_PATCH_TARGET_NOT_FOUND: 422,
    ErrorCode.ERR_PATCH_AMBIGUOUS: 422,
    ErrorCode.ERR_INVALID_REGEX: 400,
    ErrorCode.ERR_VALIDATION_FAILED: 400,
    ErrorCode.ERR_EXEC_TIMEOUT: 408,
    ErrorCode.ERR_EXEC_FAILED: 422,
}


@dataclass(frozen=True, slots=True)
class DomainError:
    """Immutable domain error compliant with RFC 7807 Problem Details."""

    code: ErrorCode
    title: str
    detail: str
    is_security_violation: bool = False
    context: dict[str, Any] = field(default_factory=dict)

    @property
    def status(self) -> int:
        return _STATUS_BY_CODE.get(self.code, 400)

    @property
    def type_uri(self) -> str:
        slug = self.code.value.lower().replace("err_", "").replace("_", "-")
        return f"urn:aegis-mcp:error:{slug}"

    def to_rfc7807(self, trace_id: str, timestamp: str | None = None) -> dict[str, Any]:
        """Serialize error to RFC 7807 Problem Details dictionary."""
        ts = timestamp or datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        payload: dict[str, Any] = {
            "type": self.type_uri,
            "title": self.title,
            "status": self.status,
            "detail": self.detail,
            "code": self.code.value,
            "trace_id": trace_id,
            "timestamp": ts,
        }
        if self.context:
            payload["context"] = self.context
        return payload

    def to_json(self, trace_id: str, timestamp: str | None = None) -> str:
        """Serialize RFC 7807 payload as compact JSON string."""
        return json.dumps(self.to_rfc7807(trace_id=trace_id, timestamp=timestamp), sort_keys=False)
