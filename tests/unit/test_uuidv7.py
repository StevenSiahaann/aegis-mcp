"""Unit tests for RFC 9562 UUIDv7 and W3C Trace Context propagation."""

from __future__ import annotations

from aegis_mcp.domain.uuidv7 import generate_span_id, generate_trace_id, generate_uuidv7
from aegis_mcp.infrastructure.observability.context import (
    bind_trace_context,
    get_current_trace_context,
    parse_or_create_trace_context,
)


def test_uuidv7_rfc9562_version_variant_and_monotonic_ordering() -> None:
    # 1. ARRANGE
    count = 200

    # 2. ACT
    generated = [generate_uuidv7() for _ in range(count)]

    # 3. ASSERT
    for u in generated:
        assert u.version == 7
        assert u.variant == "specified in RFC 4122"
    assert generated == sorted(generated)
    assert len(set(generated)) == count


def test_trace_and_span_id_formats() -> None:
    # 1. ARRANGE & 2. ACT
    trace_id = generate_trace_id()
    span_id = generate_span_id()

    # 3. ASSERT
    assert len(trace_id) == 32
    assert len(span_id) == 16
    int(trace_id, 16)
    int(span_id, 16)


def test_w3c_traceparent_parsing_and_contextvar_binding() -> None:
    # 1. ARRANGE
    upstream_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736"
    traceparent = f"00-{upstream_trace_id}-00f067aa0ba902b7-01"

    # 2. ACT
    with bind_trace_context(traceparent=traceparent, request_id=77) as active_ctx:
        inside_ctx = get_current_trace_context()

    outside_ctx = parse_or_create_trace_context(traceparent="invalid-header")

    # 3. ASSERT
    assert active_ctx.trace_id == upstream_trace_id
    assert inside_ctx.trace_id == upstream_trace_id
    assert inside_ctx.request_id == 77
    assert len(outside_ctx.trace_id) == 32
    assert outside_ctx.trace_id != upstream_trace_id

