"""Use-case handler for reading files within the sandbox perimeter."""

from __future__ import annotations

from dataclasses import replace

from aegis_mcp.application.ports import FileReadResult, FileSystemPort
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result


class ReadFileHandler:
    """Executes bounded, secret-redacted file reading within the workspace jail."""

    def __init__(self, fs: FileSystemPort, policy: SandboxPolicy) -> None:
        self._fs = fs
        self._policy = policy

    def execute(
        self,
        path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_bytes: int | None = None,
    ) -> Result[FileReadResult, DomainError]:
        if start_line < 1:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Invalid Line Range",
                    detail="start_line must be >= 1.",
                    context={"start_line": start_line},
                )
            )
        if end_line is not None and end_line < start_line:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Invalid Line Range",
                    detail=f"end_line ({end_line}) must be >= start_line ({start_line}).",
                    context={"start_line": start_line, "end_line": end_line},
                )
            )

        effective_max_bytes = self._policy.max_read_bytes
        if max_bytes is not None:
            if max_bytes < 1:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_VALIDATION_FAILED,
                        title="Invalid Byte Limit",
                        detail="max_bytes must be >= 1.",
                        context={"max_bytes": max_bytes},
                    )
                )
            effective_max_bytes = min(max_bytes, self._policy.max_read_bytes)

        result = self._fs.read_text_file(
            path,
            start_line=start_line,
            end_line=end_line,
            max_bytes=effective_max_bytes,
        )
        if result.is_err:
            return result

        read_dto = result.unwrap()
        if self._policy.wrap_untrusted_content:
            wrapped = (
                f'<untrusted_file_content path="{read_dto.relative_path}" '
                f'sha256="{read_dto.sha256}">\n'
                f"{read_dto.content}\n"
                f"</untrusted_file_content>"
            )
            return Ok(replace(read_dto, content=wrapped))

        return Ok(read_dto)

