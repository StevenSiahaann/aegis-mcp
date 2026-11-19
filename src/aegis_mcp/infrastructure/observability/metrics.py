"""Thread-safe RED (Rate, Errors, Duration) metrics collector."""

from __future__ import annotations

import threading
from collections import deque
from typing import Any


class InMemoryTelemetry:
    """Tracks tool invocation rates, domain/security error counts, and latency percentiles."""

    def __init__(self, max_samples: int = 1000) -> None:
        self._lock = threading.Lock()
        self._total_requests: int = 0
        self._total_errors: int = 0
        self._security_violations_blocked: int = 0
        self._per_tool_counts: dict[str, int] = {}
        self._latencies_ms: deque[float] = deque(maxlen=max_samples)

    def record_invocation(
        self,
        tool_name: str,
        *,
        duration_ms: float,
        is_error: bool,
        is_security_violation: bool,
    ) -> None:
        with self._lock:
            self._total_requests += 1
            if is_error:
                self._total_errors += 1
            if is_security_violation:
                self._security_violations_blocked += 1
            self._per_tool_counts[tool_name] = self._per_tool_counts.get(tool_name, 0) + 1
            self._latencies_ms.append(round(duration_ms, 3))

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            samples = sorted(self._latencies_ms)
            n = len(samples)
            if n == 0:
                p50 = p95 = p99 = 0.0
            else:
                p50 = samples[min(int(n * 0.50), n - 1)]
                p95 = samples[min(int(n * 0.95), n - 1)]
                p99 = samples[min(int(n * 0.99), n - 1)]

            return {
                "total_requests": self._total_requests,
                "total_errors": self._total_errors,
                "security_violations_blocked": self._security_violations_blocked,
                "per_tool_invocations": dict(self._per_tool_counts),
                "latency_ms": {
                    "p50": p50,
                    "p95": p95,
                    "p99": p99,
                    "sample_count": n,
                },
            }

