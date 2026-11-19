"""JSON-RPC 2.0 constants and Pydantic v2 tool input schemas for MCP."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# JSON-RPC 2.0 Standard Error Codes
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
JSONRPC_SERVER_NOT_INITIALIZED = -32002

SUPPORTED_MCP_VERSIONS: tuple[str, ...] = ("2025-03-26", "2024-11-05")
DEFAULT_MCP_VERSION = "2025-03-26"


class StrictToolArgs(BaseModel):
    """Base Pydantic v2 model forbidding undeclared extra fields."""

    model_config = ConfigDict(extra="forbid", strict=False)


class FsReadFileArgs(StrictToolArgs):
    path: str = Field(
        ...,
        description="Relative path to the file inside the workspace root.",
    )
    start_line: int = Field(
        default=1,
        ge=1,
        description="1-based starting line number (inclusive).",
    )
    end_line: int | None = Field(
        default=None,
        description="1-based ending line number (inclusive). Omit to read to end of file.",
    )
    max_bytes: int | None = Field(
        default=None,
        ge=1,
        description="Optional maximum byte cap for this read operation.",
    )


class FsListDirectoryArgs(StrictToolArgs):
    path: str = Field(
        default=".",
        description="Relative directory path inside the workspace root.",
    )
    max_depth: int = Field(
        default=2,
        ge=1,
        le=10,
        description="Maximum directory traversal depth (1 to 10).",
    )
    include_hidden: bool = Field(
        default=False,
        description="Whether to include dotfiles (sensitive files remain masked as protected).",
    )


class FsSearchTextArgs(StrictToolArgs):
    query: str = Field(
        ...,
        min_length=1,
        max_length=512,
        description="Literal string or regular expression to search for.",
    )
    path: str = Field(
        default=".",
        description="Relative directory or file path to scope the search.",
    )
    is_regex: bool = Field(
        default=False,
        description="Whether to evaluate query as a regular expression.",
    )
    max_results: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Maximum number of matching lines to return.",
    )


class FsWriteFileArgs(StrictToolArgs):
    path: str = Field(
        ...,
        description="Relative file path inside the workspace root.",
    )
    content: str = Field(
        ...,
        description="Full UTF-8 text content to write atomically.",
    )
    expected_sha256: str | None = Field(
        default=None,
        description="Optional SHA-256 hex digest of the existing file for Optimistic Concurrency Control (CAS).",
    )
    idempotency_key: str | None = Field(
        default=None,
        description="Optional unique key to guarantee idempotent replay protection on retries.",
    )


class FsPatchFileArgs(StrictToolArgs):
    path: str = Field(
        ...,
        description="Relative file path inside the workspace root.",
    )
    target: str = Field(
        ...,
        min_length=1,
        description="Exact contiguous block of existing text to replace (must appear exactly once).",
    )
    replacement: str = Field(
        ...,
        description="Replacement text block.",
    )
    expected_sha256: str | None = Field(
        default=None,
        description="Optional SHA-256 hex digest of the existing file for Optimistic Concurrency Control (CAS).",
    )
    idempotency_key: str | None = Field(
        default=None,
        description="Optional unique key to guarantee idempotent replay protection on retries.",
    )


class ExecPythonArgs(StrictToolArgs):
    code: str = Field(
        ...,
        min_length=1,
        description="Python code snippet to execute inside the isolated OS sandbox.",
    )
    args: list[str] = Field(
        default_factory=list,
        description="Optional command-line arguments passed to sys.argv.",
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0.0,
        le=120.0,
        description="Optional execution timeout in seconds (clamped by policy max_timeout_seconds).",
    )


class ExecCommandArgs(StrictToolArgs):
    binary: str = Field(
        ...,
        min_length=1,
        description="Allowlisted binary name (e.g. 'pytest', 'ruff', 'git', 'ls') executed with shell=False.",
    )
    args: list[str] = Field(
        default_factory=list,
        description="Static argument list passed directly to the binary without shell expansion.",
    )
    cwd: str = Field(
        default=".",
        description="Relative working directory inside the workspace root.",
    )
    timeout_seconds: float | None = Field(
        default=None,
        gt=0.0,
        le=120.0,
        description="Optional execution timeout in seconds (clamped by policy max_timeout_seconds).",
    )


class SandboxInspectPolicyArgs(StrictToolArgs):
    pass


def pydantic_to_mcp_input_schema(model_cls: type[BaseModel]) -> dict[str, Any]:
    """Generate a clean MCP-compatible JSON Schema from a Pydantic v2 model."""
    raw_schema = model_cls.model_json_schema()
    schema: dict[str, Any] = {
        "type": "object",
        "properties": raw_schema.get("properties", {}),
        "additionalProperties": False,
    }
    if "required" in raw_schema:
        schema["required"] = raw_schema["required"]
    return schema

