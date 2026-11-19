"""RFC 9562 UUIDv7 and W3C Trace Context identifier generation."""

from __future__ import annotations

import os
import threading
import time
import uuid

_lock = threading.Lock()
_last_ms: int = 0
_counter: int = 0


def generate_uuidv7() -> uuid.UUID:
    """Generate a time-ordered, monotonically increasing RFC 9562 UUIDv7.

    Layout (128 bits):
    - 48 bits: Unix epoch timestamp in milliseconds
    -  4 bits: Version (0b0111 = 7)
    - 12 bits: Monotonic sub-millisecond counter (rand_a)
    -  2 bits: Variant (0b10 = RFC 9562)
    - 62 bits: Cryptographically strong random payload (rand_b)
    """
    global _last_ms, _counter

    rand_bytes = os.urandom(10)
    rand_a_seed = int.from_bytes(rand_bytes[:2], "big") & 0x0FFF
    rand_b = int.from_bytes(rand_bytes[2:], "big") & ((1 << 62) - 1)

    with _lock:
        now_ms = time.time_ns() // 1_000_000
        if now_ms > _last_ms:
            _last_ms = now_ms
            _counter = rand_a_seed & 0x03FF  # leave headroom for increments
        else:
            _counter += 1
            if _counter > 0x0FFF:
                # Counter overflow within same ms: advance virtual millisecond by 1
                _last_ms += 1
                _counter = rand_a_seed & 0x03FF
            now_ms = _last_ms
        seq = _counter

    ts_48 = now_ms & ((1 << 48) - 1)
    ver_4 = 0x7
    var_2 = 0b10

    int_val = (
        (ts_48 << 80)
        | (ver_4 << 76)
        | (seq << 64)
        | (var_2 << 62)
        | rand_b
    )
    return uuid.UUID(int=int_val)


def generate_trace_id() -> str:
    """Return a 32-hex-character W3C trace_id backed by UUIDv7."""
    return generate_uuidv7().hex


def generate_span_id() -> str:
    """Return a 16-hex-character W3C span_id from cryptographic randomness."""
    raw = int.from_bytes(os.urandom(8), "big")
    if raw == 0:
        raw = 1
    return f"{raw:016x}"

