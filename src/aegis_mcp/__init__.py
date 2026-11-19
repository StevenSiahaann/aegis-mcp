"""aegis-mcp: Zero-SDK OS-Sandboxed Filesystem and Execution MCP Server."""

from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import DataClassification, SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result

__version__ = "0.1.0"

__all__ = [
    "DataClassification",
    "DomainError",
    "Err",
    "ErrorCode",
    "Ok",
    "Result",
    "SandboxPolicy",
    "__version__",
]

