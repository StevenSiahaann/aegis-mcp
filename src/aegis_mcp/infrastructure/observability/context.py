"""W3C Trace Context propagation via Python contextvars (AsyncLocalStorage equivalent)."""

from __future__ import annotations

import contextvars
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass

from aegis_mcp.domain.uuidv7 import generate_span_id, generate_trace_id

_W3C_TRACEPARENT_RE = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$")


@dataclass(frozen=True, slots=True)
class TraceContext:
    """Immutable W3C trace context bound to the current request execution scope."""

    trace_id: str
    span_id: str
    request_id: str | int | None = None


_current_trace_ctx: contextvars.ContextVar[TraceContext | None] = contextvars.ContextVar(
    "aegis_trace_ctx", default=None
)


def parse_or_create_trace_context(
    traceparent: str | None = None,
    request_id: str | int | None = None,
) -> TraceContext:
    """Extract trace_id from a valid W3C traceparent string or generate a fresh UUIDv7 trace."""
    if traceparent:
        match = _W3C_TRACEPARENT_RE.match(traceparent.strip().lower())
        if match:
            trace_id = match.group(1)
            if trace_id != "0" * 32:
                return TraceContext(
                    trace_id=trace_id,
                    span_id=generate_span_id(),
                    request_id=request_id,
                )
    return TraceContext(
        trace_id=generate_trace_id(),
        span_id=generate_span_id(),
        request_id=request_id,
    )


def get_current_trace_context() -> TraceContext:
    """Return active TraceContext or generate an ephemeral one if called outside request scope."""
    ctx = _current_trace_ctx.get()
    if ctx is None:
        return TraceContext(trace_id=generate_trace_id(), span_id=generate_span_id())
    return ctx


@contextmanager
def bind_trace_context(
    traceparent: str | None = None,
    request_id: str | int | None = None,
) -> Iterator[TraceContext]:
    """Context manager binding a W3C TraceContext for the duration of a request."""
    ctx = parse_or_create_trace_context(traceparent=traceparent, request_id=request_id)
    token = _current_trace_ctx.set(ctx)
    try:
        yield ctx
    finally:
        _current_trace_ctx.reset(token)

