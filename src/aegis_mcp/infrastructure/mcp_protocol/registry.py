"""MCP Tool Registry mapping tool schemas to single-responsibility use-case handlers."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from pydantic import BaseModel, ValidationError

from aegis_mcp.application.handlers.inspect_policy import InspectPolicyHandler
from aegis_mcp.application.handlers.list_directory import ListDirectoryHandler
from aegis_mcp.application.handlers.patch_file import PatchFileHandler
from aegis_mcp.application.handlers.read_file import ReadFileHandler
from aegis_mcp.application.handlers.run_command import RunCommandHandler
from aegis_mcp.application.handlers.run_python import RunPythonHandler
from aegis_mcp.application.handlers.search_text import SearchTextHandler
from aegis_mcp.application.handlers.write_file import WriteFileHandler
from aegis_mcp.application.idempotency import IdempotencyStore
from aegis_mcp.application.ports import (
    FilePatchResult,
    FileSystemPort,
    FileWriteResult,
    SandboxRunnerPort,
    TelemetryPort,
)
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Result
from aegis_mcp.infrastructure.mcp_protocol.models import (
    ExecCommandArgs,
    ExecPythonArgs,
    FsListDirectoryArgs,
    FsPatchFileArgs,
    FsReadFileArgs,
    FsSearchTextArgs,
    FsWriteFileArgs,
    SandboxInspectPolicyArgs,
    pydantic_to_mcp_input_schema,
)
from aegis_mcp.infrastructure.observability.context import get_current_trace_context
from aegis_mcp.infrastructure.observability.logger import NDJSONLogger

_BULK_PAYLOAD_KEYS: frozenset[str] = frozenset({"content", "code", "target", "replacement"})


def _summarize_audit_arguments(args_dict: dict[str, Any]) -> dict[str, Any]:
    """Replace large or potentially sensitive payload fields with compact size + SHA-256 metadata."""
    summary: dict[str, Any] = {}
    for k, v in args_dict.items():
        if k in _BULK_PAYLOAD_KEYS and isinstance(v, str):
            raw = v.encode("utf-8")
            summary[k] = {
                "bytes": len(raw),
                "sha256_prefix": hashlib.sha256(raw).hexdigest()[:16],
            }
        else:
            summary[k] = v
    return summary


@dataclass(frozen=True, slots=True)
class ToolDefinition:
    """Metadata and execution adapter for an exposed MCP tool."""

    name: str
    description: str
    args_model: type[BaseModel]
    invoker: Callable[[BaseModel], Result[Any, DomainError]]
    annotations: dict[str, bool] = field(default_factory=dict)

    def to_mcp_descriptor(self) -> dict[str, Any]:
        desc: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "inputSchema": pydantic_to_mcp_input_schema(self.args_model),
        }
        if self.annotations:
            desc["annotations"] = dict(self.annotations)
        return desc


class ToolRegistry:
    """Registers and dispatches all 8 sandboxed MCP capability tools."""

    def __init__(
        self,
        *,
        policy: SandboxPolicy,
        fs: FileSystemPort,
        runner: SandboxRunnerPort,
        telemetry: TelemetryPort,
        logger: NDJSONLogger,
    ) -> None:
        self._policy = policy
        self._telemetry = telemetry
        self._logger = logger

        write_idemp: IdempotencyStore[FileWriteResult] = IdempotencyStore()
        patch_idemp: IdempotencyStore[FilePatchResult] = IdempotencyStore()

        self._read_handler = ReadFileHandler(fs=fs, policy=policy)
        self._list_handler = ListDirectoryHandler(fs=fs, policy=policy)
        self._search_handler = SearchTextHandler(fs=fs, policy=policy)
        self._write_handler = WriteFileHandler(fs=fs, policy=policy, idempotency_store=write_idemp)
        self._patch_handler = PatchFileHandler(fs=fs, policy=policy, idempotency_store=patch_idemp)
        self._python_handler = RunPythonHandler(runner=runner, policy=policy)
        self._command_handler = RunCommandHandler(runner=runner, policy=policy)
        self._inspect_handler = InspectPolicyHandler(policy=policy, telemetry=telemetry)

        self._tools: dict[str, ToolDefinition] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        defs = [
            ToolDefinition(
                name="fs_read_file",
                description=(
                    "Read a UTF-8 text file inside the sandbox workspace root with line-range filtering, "
                    "canonical path jail verification, sensitive credential blocking, and SHA-256 digest."
                ),
                args_model=FsReadFileArgs,
                invoker=self._invoke_read_file,
                annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            ),
            ToolDefinition(
                name="fs_list_directory",
                description=(
                    "List files and directories inside the sandbox workspace root using bounded iterative "
                    "BFS traversal. Sensitive credential files are flagged as 'protected_sensitive'."
                ),
                args_model=FsListDirectoryArgs,
                invoker=self._invoke_list_directory,
                annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            ),
            ToolDefinition(
                name="fs_search_text",
                description=(
                    "Search for literal text or regular expressions across files in the sandbox workspace "
                    "root with automatic binary skipping, ReDoS protection, and inline secret redaction."
                ),
                args_model=FsSearchTextArgs,
                invoker=self._invoke_search_text,
                annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            ),
            ToolDefinition(
                name="fs_write_file",
                description=(
                    "Atomically write a UTF-8 text file inside the workspace root using O_NOFOLLOW temp-file "
                    "swap, optional Optimistic Concurrency Control (expected_sha256), and idempotency_key."
                ),
                args_model=FsWriteFileArgs,
                invoker=self._invoke_write_file,
                annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False},
            ),
            ToolDefinition(
                name="fs_patch_file",
                description=(
                    "Atomically replace an exact target text block inside a workspace file with optional "
                    "SHA-256 Optimistic Concurrency Control (expected_sha256) and idempotency_key."
                ),
                args_model=FsPatchFileArgs,
                invoker=self._invoke_patch_file,
                annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            ),
            ToolDefinition(
                name="exec_python",
                description=(
                    "Execute an isolated Python code snippet inside the sandbox with zero-trust scrubbed "
                    "environment variables, POSIX resource limits, and process-group timeout SIGKILL."
                ),
                args_model=ExecPythonArgs,
                invoker=self._invoke_exec_python,
                annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
            ),
            ToolDefinition(
                name="exec_command",
                description=(
                    "Execute an allowlisted binary (e.g. pytest, ruff, mypy, git, ls) with shell=False, "
                    "argument safety guards, scrubbed environment, and process-group timeout SIGKILL."
                ),
                args_model=ExecCommandArgs,
                invoker=self._invoke_exec_command,
                annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False},
            ),
            ToolDefinition(
                name="sandbox_inspect_policy",
                description=(
                    "Inspect the active sandbox security policy, resource limits, capability flags, "
                    "allowed binaries, and runtime RED telemetry metrics."
                ),
                args_model=SandboxInspectPolicyArgs,
                invoker=self._invoke_inspect_policy,
                annotations={"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
            ),
        ]
        for d in defs:
            self._tools[d.name] = d

    def _invoke_read_file(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, FsReadFileArgs)
        return self._read_handler.execute(
            model.path,
            start_line=model.start_line,
            end_line=model.end_line,
            max_bytes=model.max_bytes,
        )

    def _invoke_list_directory(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, FsListDirectoryArgs)
        return self._list_handler.execute(
            model.path,
            max_depth=model.max_depth,
            include_hidden=model.include_hidden,
        )

    def _invoke_search_text(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, FsSearchTextArgs)
        return self._search_handler.execute(
            model.query,
            path=model.path,
            is_regex=model.is_regex,
            max_results=model.max_results,
        )

    def _invoke_write_file(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, FsWriteFileArgs)
        return self._write_handler.execute(
            model.path,
            model.content,
            expected_sha256=model.expected_sha256,
            idempotency_key=model.idempotency_key,
        )

    def _invoke_patch_file(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, FsPatchFileArgs)
        return self._patch_handler.execute(
            model.path,
            model.target,
            model.replacement,
            expected_sha256=model.expected_sha256,
            idempotency_key=model.idempotency_key,
        )

    def _invoke_exec_python(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, ExecPythonArgs)
        return self._python_handler.execute(
            model.code,
            args=model.args,
            timeout_seconds=model.timeout_seconds,
        )

    def _invoke_exec_command(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, ExecCommandArgs)
        return self._command_handler.execute(
            model.binary,
            args=model.args,
            cwd=model.cwd,
            timeout_seconds=model.timeout_seconds,
        )

    def _invoke_inspect_policy(self, model: BaseModel) -> Result[Any, DomainError]:
        assert isinstance(model, SandboxInspectPolicyArgs)
        return self._inspect_handler.execute()

    def list_tool_descriptors(self) -> list[dict[str, Any]]:
        return [tool.to_mcp_descriptor() for tool in self._tools.values()]

    def has_tool(self, name: str) -> bool:
        return name in self._tools

    def call_tool(self, name: str, raw_arguments: dict[str, Any] | None) -> dict[str, Any]:
        """Validate arguments, execute use-case handler, log audit trail, and return MCP tool result."""
        tool_def = self._tools[name]
        args_dict = raw_arguments if raw_arguments is not None else {}
        trace_ctx = get_current_trace_context()
        start_ns = time.perf_counter_ns()

        try:
            validated_args = tool_def.args_model.model_validate(args_dict)
        except ValidationError as exc:
            duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0
            dom_err = DomainError(
                code=ErrorCode.ERR_VALIDATION_FAILED,
                title="Tool Argument Validation Failed",
                detail=str(exc.errors(include_url=False)),
                context={"tool": name, "validation_errors": exc.errors(include_url=False)},
            )
            self._telemetry.record_invocation(
                name,
                duration_ms=duration_ms,
                is_error=True,
                is_security_violation=False,
            )
            self._logger.warn(
                "TOOL_VALIDATION_FAILED",
                f"Argument validation failed for tool '{name}'",
                context={"tool": name, "arguments": _summarize_audit_arguments(args_dict)},
                duration_ms=duration_ms,
            )
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": dom_err.to_json(trace_id=trace_ctx.trace_id),
                    }
                ],
            }

        result = tool_def.invoker(validated_args)
        duration_ms = (time.perf_counter_ns() - start_ns) / 1_000_000.0

        if result.is_err:
            err = result.unwrap_err()
            self._telemetry.record_invocation(
                name,
                duration_ms=duration_ms,
                is_error=True,
                is_security_violation=err.is_security_violation,
            )
            action = "SANDBOX_VIOLATION_BLOCKED" if err.is_security_violation else "TOOL_DOMAIN_ERROR"
            self._logger.warn(
                action,
                f"{err.title}: {err.detail}",
                context={
                    "tool": name,
                    "error_code": err.code.value,
                    "is_security_violation": err.is_security_violation,
                    "arguments": _summarize_audit_arguments(args_dict),
                },
                duration_ms=duration_ms,
                is_audit_event=True,
            )
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": err.to_json(trace_id=trace_ctx.trace_id),
                    }
                ],
            }

        val = result.unwrap()
        self._telemetry.record_invocation(
            name,
            duration_ms=duration_ms,
            is_error=False,
            is_security_violation=False,
        )
        is_mutating_or_exec = name in ("fs_write_file", "fs_patch_file", "exec_python", "exec_command")
        self._logger.info(
            "TOOL_EXECUTED",
            f"Tool '{name}' completed successfully",
            context={"tool": name, "arguments": _summarize_audit_arguments(args_dict)},
            duration_ms=duration_ms,
            is_audit_event=is_mutating_or_exec,
        )

        payload_dict = val if isinstance(val, dict) else asdict(val)
        return {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(payload_dict, sort_keys=False),
                }
            ],
        }

