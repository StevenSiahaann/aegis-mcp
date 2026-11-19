"""Single-line NDJSON structured logger emitting strictly to stderr with automatic PII/Secret redaction."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from aegis_mcp.domain.matchers import SecretRedactor
from aegis_mcp.domain.uuidv7 import generate_uuidv7
from aegis_mcp.infrastructure.observability.context import get_current_trace_context


class NDJSONLogger:
    """Structured single-line JSON logger writing to stderr and optional append-only audit log."""

    def __init__(
        self,
        service_name: str = "aegis-mcp",
        stream: TextIO | None = None,
        audit_log_path: Path | None = None,
    ) -> None:
        self._service = service_name
        self._stream = stream if stream is not None else sys.stderr
        self._audit_log_path = audit_log_path
        self._lock = threading.Lock()

    def _emit(
        self,
        level: str,
        action: str,
        message: str,
        context: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        is_audit_event: bool = False,
    ) -> None:
        trace_ctx = get_current_trace_context()
        now_utc = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

        safe_message, _ = SecretRedactor.redact_text(message)
        safe_context = SecretRedactor.redact_structure(context or {})

        entry: dict[str, Any] = {
            "timestamp": now_utc,
            "level": level,
            "service": self._service,
            "trace_id": trace_ctx.trace_id,
            "span_id": trace_ctx.span_id,
            "action": action,
            "message": safe_message,
            "context": safe_context,
        }
        if trace_ctx.request_id is not None:
            entry["request_id"] = trace_ctx.request_id
        if duration_ms is not None:
            entry["duration_ms"] = round(duration_ms, 3)
        if is_audit_event:
            entry["audit_id"] = str(generate_uuidv7())

        line = json.dumps(entry, separators=(",", ":"), sort_keys=False) + "\n"

        with self._lock:
            self._stream.write(line)
            self._stream.flush()
            if is_audit_event and self._audit_log_path is not None:
                with contextlib.suppress(OSError):
                    fd = os.open(
                        str(self._audit_log_path),
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
                        0o600,
                    )
                    try:
                        os.write(fd, line.encode("utf-8"))
                    finally:
                        os.close(fd)

    def info(
        self,
        action: str,
        message: str,
        context: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        is_audit_event: bool = False,
    ) -> None:
        self._emit("INFO", action, message, context=context, duration_ms=duration_ms, is_audit_event=is_audit_event)

    def warn(
        self,
        action: str,
        message: str,
        context: dict[str, Any] | None = None,
        duration_ms: float | None = None,
        is_audit_event: bool = True,
    ) -> None:
        self._emit("WARN", action, message, context=context, duration_ms=duration_ms, is_audit_event=is_audit_event)

    def error(
        self,
        action: str,
        message: str,
        context: dict[str, Any] | None = None,
        duration_ms: float | None = None,
    ) -> None:
        self._emit("ERROR", action, message, context=context, duration_ms=duration_ms, is_audit_event=True)
