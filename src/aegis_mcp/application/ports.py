"""Outward port interfaces and application DTOs for Clean Architecture boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from aegis_mcp.domain.errors import DomainError
from aegis_mcp.domain.result import Result


@dataclass(frozen=True, slots=True)
class FileReadResult:
    """Result DTO for a bounded, secret-scrubbed file read operation."""

    relative_path: str
    content: str
    sha256: str
    total_bytes: int
    start_line: int
    end_line: int
    total_lines: int
    truncated: bool
    secrets_redacted: int


@dataclass(frozen=True, slots=True)
class DirectoryEntryItem:
    """Single item in a directory listing."""

    relative_path: str
    entry_type: str  # "file" | "directory" | "protected_sensitive"
    size_bytes: int | None


@dataclass(frozen=True, slots=True)
class DirectoryListResult:
    """Result DTO for an iterative bounded directory listing."""

    root_relative_path: str
    entries: tuple[DirectoryEntryItem, ...]
    truncated: bool


@dataclass(frozen=True, slots=True)
class SearchMatchItem:
    """Single text match in a workspace search."""

    relative_path: str
    line_number: int
    line_text: str


@dataclass(frozen=True, slots=True)
class TextSearchResult:
    """Result DTO for a streaming workspace text search."""

    query: str
    matches: tuple[SearchMatchItem, ...]
    files_scanned: int
    files_skipped_sensitive: int
    truncated: bool
    secrets_redacted: int


@dataclass(frozen=True, slots=True)
class FileWriteResult:
    """Result DTO for an atomic file write operation."""

    relative_path: str
    bytes_written: int
    previous_sha256: str | None
    new_sha256: str
    created: bool
    idempotent_replayed: bool = False


@dataclass(frozen=True, slots=True)
class FilePatchResult:
    """Result DTO for an atomic exact-block file patch operation."""

    relative_path: str
    bytes_written: int
    previous_sha256: str
    new_sha256: str
    idempotent_replayed: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """Result DTO for a sandboxed subprocess execution."""

    command_summary: str
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    secrets_redacted: int


class FileSystemPort(Protocol):
    """Port contract for OS-jailed filesystem operations."""

    def resolve_safe_path(
        self,
        rel_path: str,
        *,
        must_exist: bool = True,
        allow_directory: bool = False,
        check_sensitive: bool = True,
    ) -> Result[Path, DomainError]: ...

    def read_text_file(
        self,
        rel_path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_bytes: int | None = None,
    ) -> Result[FileReadResult, DomainError]: ...

    def write_text_file(
        self,
        rel_path: str,
        content: str,
        *,
        expected_sha256: str | None = None,
    ) -> Result[FileWriteResult, DomainError]: ...

    def patch_text_file(
        self,
        rel_path: str,
        target: str,
        replacement: str,
        *,
        expected_sha256: str | None = None,
    ) -> Result[FilePatchResult, DomainError]: ...

    def list_directory(
        self,
        rel_path: str = ".",
        *,
        max_depth: int = 2,
        include_hidden: bool = False,
    ) -> Result[DirectoryListResult, DomainError]: ...

    def search_text(
        self,
        query: str,
        *,
        rel_path: str = ".",
        is_regex: bool = False,
        max_results: int = 50,
    ) -> Result[TextSearchResult, DomainError]: ...


class SandboxRunnerPort(Protocol):
    """Port contract for isolated subprocess execution."""

    def run_python(
        self,
        code: str,
        *,
        args: list[str] | None = None,
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]: ...

    def run_command(
        self,
        binary: str,
        *,
        args: list[str] | None = None,
        cwd_rel: str = ".",
        timeout_seconds: float | None = None,
    ) -> Result[ExecutionResult, DomainError]: ...


class TelemetryPort(Protocol):
    """Port contract for RED metrics and security violation telemetry."""

    def record_invocation(
        self,
        tool_name: str,
        *,
        duration_ms: float,
        is_error: bool,
        is_security_violation: bool,
    ) -> None: ...

    def snapshot(self) -> dict[str, Any]: ...

