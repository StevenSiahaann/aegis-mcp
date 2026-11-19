"""CLI entrypoint for launching the aegis-mcp stdio server."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from aegis_mcp.domain.policy import DEFAULT_ALLOWED_BINARIES, SandboxPolicy
from aegis_mcp.infrastructure.mcp_protocol.stdio_server import StdioMCPServer
from aegis_mcp.infrastructure.observability.logger import NDJSONLogger


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis-mcp",
        description="Zero-SDK OS-Sandboxed Filesystem & Execution Capability MCP Server",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Canonical workspace directory root for the sandbox jail (default: current working directory).",
    )
    parser.add_argument(
        "--allow-write",
        action="store_true",
        default=False,
        help="Enable atomic file write and patch capabilities (default: False / read-only).",
    )
    parser.add_argument(
        "--allow-exec",
        action="store_true",
        default=False,
        help="Enable isolated Python and allowlisted binary execution capabilities (default: False).",
    )
    parser.add_argument(
        "--allow-symlinks",
        action="store_true",
        default=False,
        help="Allow following symbolic links whose resolved target remains strictly inside --root.",
    )
    parser.add_argument(
        "--enable-seatbelt",
        action="store_true",
        default=False,
        help="Wrap subprocesses with macOS sandbox-exec (Seatbelt) kernel profile on Darwin.",
    )
    parser.add_argument(
        "--wrap-untrusted",
        action="store_true",
        default=False,
        help="Wrap file read contents in <untrusted_file_content> XML delimiters (OWASP LLM01).",
    )
    parser.add_argument(
        "--max-read-bytes",
        type=int,
        default=65_536,
        help="Maximum bytes returned per file read call (default: 65536).",
    )
    parser.add_argument(
        "--max-output-bytes",
        type=int,
        default=65_536,
        help="Maximum stdout/stderr bytes captured per subprocess execution (default: 65536).",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Default subprocess timeout in seconds (default: 5.0).",
    )
    parser.add_argument(
        "--max-timeout",
        type=float,
        default=30.0,
        help="Maximum allowed subprocess timeout in seconds (default: 30.0).",
    )
    parser.add_argument(
        "--allowed-binaries",
        type=str,
        default=None,
        help="Comma-separated list of allowed binaries for exec_command.",
    )
    parser.add_argument(
        "--extra-read-paths",
        type=str,
        default=None,
        help="Comma-separated list of additional read-only directory paths permitted inside the kernel sandbox.",
    )
    parser.add_argument(
        "--audit-log",
        type=Path,
        default=None,
        help="Optional file path for append-only NDJSON security audit logs.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    binaries = DEFAULT_ALLOWED_BINARIES
    if args.allowed_binaries is not None:
        parsed_bins = frozenset(b.strip() for b in args.allowed_binaries.split(",") if b.strip())
        binaries = parsed_bins

    extra_reads: tuple[Path, ...] = ()
    if args.extra_read_paths is not None:
        extra_reads = tuple(
            Path(p.strip()) for p in args.extra_read_paths.split(",") if p.strip()
        )

    try:
        policy = SandboxPolicy(
            workspace_root=args.root,
            allow_write=args.allow_write,
            allow_exec=args.allow_exec,
            allow_symlinks_within_jail=args.allow_symlinks,
            enable_seatbelt=args.enable_seatbelt,
            wrap_untrusted_content=args.wrap_untrusted,
            max_read_bytes=args.max_read_bytes,
            max_output_bytes=args.max_output_bytes,
            default_timeout_seconds=args.timeout,
            max_timeout_seconds=args.max_timeout,
            allowed_binaries=binaries,
            extra_read_paths=extra_reads,
        )
    except ValueError as exc:
        logger = NDJSONLogger(service_name="aegis-mcp", stream=sys.stderr)
        logger.error("INVALID_POLICY_CONFIG", str(exc))
        return 2

    logger = NDJSONLogger(
        service_name="aegis-mcp",
        stream=sys.stderr,
        audit_log_path=args.audit_log,
    )
    server = StdioMCPServer(policy=policy, logger=logger)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

