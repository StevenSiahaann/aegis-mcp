"""Use-case handler for listing directory structures within the sandbox perimeter."""

from __future__ import annotations

from aegis_mcp.application.ports import DirectoryListResult, FileSystemPort
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Result


class ListDirectoryHandler:
    """Executes bounded iterative directory traversal within the workspace jail."""

    def __init__(self, fs: FileSystemPort, policy: SandboxPolicy) -> None:
        self._fs = fs
        self._policy = policy

    def execute(
        self,
        path: str = ".",
        *,
        max_depth: int = 2,
        include_hidden: bool = False,
    ) -> Result[DirectoryListResult, DomainError]:
        if max_depth < 1:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Invalid Traversal Depth",
                    detail="max_depth must be >= 1.",
                    context={"max_depth": max_depth},
                )
            )
        clamped_depth = min(max_depth, self._policy.max_dir_depth)
        return self._fs.list_directory(
            path,
            max_depth=clamped_depth,
            include_hidden=include_hidden,
        )

