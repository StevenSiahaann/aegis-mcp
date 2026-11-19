"""Use-case handler for searching text across workspace files within the sandbox perimeter."""

from __future__ import annotations

from aegis_mcp.application.ports import FileSystemPort, TextSearchResult
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Result


class SearchTextHandler:
    """Executes streaming text search with ReDoS guard and secret redaction."""

    def __init__(self, fs: FileSystemPort, policy: SandboxPolicy) -> None:
        self._fs = fs
        self._policy = policy

    def execute(
        self,
        query: str,
        *,
        path: str = ".",
        is_regex: bool = False,
        max_results: int = 50,
    ) -> Result[TextSearchResult, DomainError]:
        if not query or not query.strip():
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Empty Search Query",
                    detail="Search query must not be empty.",
                )
            )
        if len(query) > 512:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Query Too Long",
                    detail="Search query must not exceed 512 characters.",
                    context={"query_length": len(query)},
                )
            )
        if max_results < 1:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Invalid Max Results",
                    detail="max_results must be >= 1.",
                )
            )

        clamped_max = min(max_results, self._policy.max_search_results)
        return self._fs.search_text(
            query,
            rel_path=path,
            is_regex=is_regex,
            max_results=clamped_max,
        )

