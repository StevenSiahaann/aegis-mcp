"""Sandbox security policy domain entity and 4-tier data classification."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path


class DataClassification(StrEnum):
    """4-Tier Enterprise Data Sensitivity Classification."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL_PII = "CONFIDENTIAL_PII"
    RESTRICTED_SECRET = "RESTRICTED_SECRET"


DEFAULT_ALLOWED_BINARIES: frozenset[str] = frozenset(
    {
        "pytest",
        "ruff",
        "mypy",
        "git",
        "ls",
        "wc",
        "head",
        "tail",
        "python3",
        "python",
    }
)


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Rich Domain Entity enforcing sandbox configuration invariants."""

    workspace_root: Path
    allow_write: bool = False
    allow_exec: bool = False
    allow_symlinks_within_jail: bool = False
    enable_seatbelt: bool = True
    require_kernel_sandbox: bool = True
    allow_subprocess: bool = False
    wrap_untrusted_content: bool = False
    max_read_bytes: int = 65_536
    max_write_bytes: int = 2_097_152
    max_output_bytes: int = 65_536
    max_timeout_seconds: float = 30.0
    default_timeout_seconds: float = 5.0
    max_dir_depth: int = 10
    max_search_results: int = 100
    rlimit_cpu_seconds: int = 10
    rlimit_fsize_bytes: int = 10_485_760
    rlimit_as_bytes: int = 536_870_912
    rlimit_nofile: int = 64
    allowed_binaries: frozenset[str] = field(default_factory=lambda: DEFAULT_ALLOWED_BINARIES)

    def __post_init__(self) -> None:
        resolved_root = Path(os.path.realpath(self.workspace_root))
        if not resolved_root.exists():
            raise ValueError(f"Workspace root does not exist: {self.workspace_root}")
        if not resolved_root.is_dir():
            raise ValueError(f"Workspace root is not a directory: {self.workspace_root}")
        if resolved_root == Path("/"):
            raise ValueError("Workspace root cannot be the filesystem root '/'")
        object.__setattr__(self, "workspace_root", resolved_root)

        if self.max_read_bytes <= 0 or self.max_read_bytes > 10_485_760:
            raise ValueError("max_read_bytes must be between 1 and 10,485,760 bytes")
        if self.max_write_bytes <= 0 or self.max_write_bytes > 20_971_520:
            raise ValueError("max_write_bytes must be between 1 and 20,971,520 bytes")
        if self.max_output_bytes <= 0 or self.max_output_bytes > 1_048_576:
            raise ValueError("max_output_bytes must be between 1 and 1,048,576 bytes")
        if self.max_timeout_seconds <= 0 or self.max_timeout_seconds > 120.0:
            raise ValueError("max_timeout_seconds must be between 0.1 and 120.0 seconds")
        if self.default_timeout_seconds <= 0 or self.default_timeout_seconds > self.max_timeout_seconds:
            raise ValueError("default_timeout_seconds must be positive and <= max_timeout_seconds")
        if self.max_dir_depth < 1 or self.max_dir_depth > 25:
            raise ValueError("max_dir_depth must be between 1 and 25")

    @property
    def sandbox_scratch_dir(self) -> Path:
        """Internal scratch directory inside the canonical workspace root."""
        return self.workspace_root / ".aegis-sandbox" / "tmp"

    def clamp_timeout(self, requested_timeout: float | None) -> float:
        """Clamp caller-requested timeout within policy bounds."""
        if requested_timeout is None or requested_timeout <= 0:
            return self.default_timeout_seconds
        return min(float(requested_timeout), self.max_timeout_seconds)

