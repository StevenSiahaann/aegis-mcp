"""Unicode NFC normalization, sensitive file denylist matching, secret redaction, and command argument guards."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from typing import Any

from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result


def normalize_nfc(text: str) -> str:
    """Normalize string to Unicode Form C (NFC) to prevent macOS APFS NFD bypasses."""
    return unicodedata.normalize("NFC", text)


_SAFE_ENV_TEMPLATES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.template",
        ".env.sample",
        ".env.dist",
    }
)

_SENSITIVE_EXACT_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".htpasswd",
        ".pgpass",
        "kubeconfig",
        "credentials.json",
        "client_secret.json",
        "id_rsa",
        "id_rsa.pub",
        "id_ed25519",
        "id_ed25519.pub",
        "id_ecdsa",
        "id_dsa",
    }
)

_SENSITIVE_SUFFIXES: tuple[str, ...] = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".tfstate",
    ".tfstate.backup",
    ".tfvars",
    ".kdbx",
)

_SENSITIVE_GLOBS: tuple[str, ...] = (
    ".env.*",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*service-account*.json",
    "*credentials*.json",
    "*secret*.json",
    "*private*key*",
)

_SENSITIVE_REL_PATH_PATTERNS: tuple[str, ...] = (
    ".git/config",
    ".git/credentials",
    ".git-credentials",
    ".aws/credentials",
    ".aws/config",
    ".ssh/*",
    ".gnupg/*",
)


class SensitiveFileMatcher:
    """Determines whether a relative path inside the workspace is restricted."""

    @staticmethod
    def is_sensitive(rel_posix_path: str) -> tuple[bool, str]:
        """Return (is_blocked, reason) for a workspace-relative POSIX path."""
        normalized = normalize_nfc(rel_posix_path).strip("/")
        if not normalized or normalized == ".":
            return False, ""

        lower_rel = normalized.lower()
        parts = lower_rel.split("/")
        filename = parts[-1]

        # 1. Allow explicit safe templates (.env.example, .env.template, etc.)
        if filename in _SAFE_ENV_TEMPLATES:
            return False, ""

        # 2. Check exact sensitive filenames in any path component
        for part in parts:
            if part in _SENSITIVE_EXACT_NAMES and part not in _SAFE_ENV_TEMPLATES:
                return True, f"Path component '{part}' matches protected credential file list"

        # 3. Check relative path patterns (.git/config, .ssh/*, etc.)
        for rel_pat in _SENSITIVE_REL_PATH_PATTERNS:
            if (
                lower_rel == rel_pat
                or lower_rel.endswith(f"/{rel_pat}")
                or fnmatch.fnmatch(lower_rel, rel_pat)
                or fnmatch.fnmatch(lower_rel, f"*/{rel_pat}")
            ):
                return True, f"Path matches protected configuration pattern '{rel_pat}'"

        # 4. Check file extension suffixes
        for suffix in _SENSITIVE_SUFFIXES:
            if filename.endswith(suffix):
                return True, f"File extension '{suffix}' is classified as RESTRICTED_SECRET"

        # 5. Check filename globs
        for glob_pat in _SENSITIVE_GLOBS:
            if fnmatch.fnmatch(filename, glob_pat):
                return True, f"Filename '{filename}' matches protected secret pattern '{glob_pat}'"

        return False, ""


# Pre-compiled high-performance regex patterns for secret and PII scrubbing
_SENSITIVE_KEY_RE = re.compile(
    r"(?:password|passphrase|secret|token|authorization|api[-_]?key|credit[-_]?card|"
    r"card[-_]?number|cvv|pin|nik|ssn|private[-_]?key|client[-_]?secret|access[-_]?key|"
    r"dsn|connection[-_]?string)",
    re.IGNORECASE,
)

_INLINE_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # PEM Private Key Blocks
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PEM_PRIVATE_KEY]",
    ),
    # AWS Access Key ID
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_AWS_KEY]"),
    # GitHub Personal Access / Fine-grained / OAuth Tokens
    (
        re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{20,255}\b"),
        "[REDACTED_GITHUB_TOKEN]",
    ),
    # OpenAI / Anthropic / Stripe Secret Keys
    (
        re.compile(r"\bsk-(?:proj-|ant-|live-|test-)?[a-zA-Z0-9_-]{20,255}\b"),
        "[REDACTED_API_KEY]",
    ),
    # Google API Keys
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED_GOOGLE_API_KEY]"),
    # Slack Tokens
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,255}\b"), "[REDACTED_SLACK_TOKEN]"),
    # Authorization Bearer / Basic Headers
    (
        re.compile(r"(?i)\b(Authorization\s*:\s*(?:Bearer|Basic)\s+)[^\s\"',;]+"),
        r"\1[REDACTED_AUTH_TOKEN]",
    ),
    # Generic env/config key=value assignments for secret keys (skip already redacted placeholders)
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[:=]\s*['\"]?)(?!\[REDACTED_)([^\s'\"\n]{8,})(['\"]?)"
        ),
        r"\1[REDACTED_SECRET]\3",
    ),
)


class SecretRedactor:
    """Scrubs Tier-3/Tier-4 secrets from text outputs and structured log dictionaries."""

    @staticmethod
    def redact_text(text: str) -> tuple[str, int]:
        """Redact inline credentials from text. Returns (scrubbed_text, redaction_count)."""
        if not text:
            return text, 0
        total_redactions = 0
        current = text
        for pattern, replacement in _INLINE_SECRET_PATTERNS:
            current, count = pattern.subn(replacement, current)
            total_redactions += count
        return current, total_redactions

    @classmethod
    def redact_structure(cls, obj: Any, _depth: int = 0) -> Any:
        """Recursively scrub dictionaries, lists, and strings for structured logging."""
        if _depth > 12:
            return "[MAX_DEPTH_TRUNCATED]"
        if isinstance(obj, dict):
            cleaned: dict[str, Any] = {}
            for k, v in obj.items():
                key_str = str(k)
                if _SENSITIVE_KEY_RE.search(key_str):
                    cleaned[key_str] = "[REDACTED]"
                else:
                    cleaned[key_str] = cls.redact_structure(v, _depth + 1)
            return cleaned
        if isinstance(obj, (list, tuple)):
            return [cls.redact_structure(item, _depth + 1) for item in obj]
        if isinstance(obj, str):
            redacted_str, _ = cls.redact_text(obj)
            return redacted_str
        return obj


_FORBIDDEN_GIT_SUBCOMMANDS: frozenset[str] = frozenset(
    {
        "push",
        "pull",
        "fetch",
        "clone",
        "remote",
        "credential",
        "daemon",
        "instaweb",
        "filter-branch",
        " gc",
    }
)

_FORBIDDEN_GIT_FLAGS: tuple[str, ...] = (
    "--global",
    "--system",
    "--upload-pack",
    "--receive-pack",
    "--exec",
    "core.sshcommand",
    "core.fsmonitor",
    "core.editor",
    "alias.",
    "--force",
)


class CommandArgumentGuard:
    """Validates binary allowlist and prevents dangerous subcommands or flag injections."""

    @staticmethod
    def validate(
        binary: str, args: list[str], policy: SandboxPolicy
    ) -> Result[tuple[str, list[str]], DomainError]:
        """Verify binary and argument vector comply with zero-trust command policy."""
        clean_bin = normalize_nfc(binary).strip()
        if not clean_bin or "\x00" in clean_bin:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_COMMAND_NOT_ALLOWED,
                    title="Invalid Binary Identifier",
                    detail="Binary name must be a non-empty string without null bytes.",
                    is_security_violation=True,
                )
            )

        if "/" in clean_bin or "\\" in clean_bin or ".." in clean_bin:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_COMMAND_NOT_ALLOWED,
                    title="Path Binary Execution Forbidden",
                    detail=(
                        f"Binary '{clean_bin}' contains path separators. "
                        "Only bare allowlisted binary names are permitted."
                    ),
                    is_security_violation=True,
                    context={"binary": clean_bin},
                )
            )

        if clean_bin not in policy.allowed_binaries:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_COMMAND_NOT_ALLOWED,
                    title="Binary Not In Allowlist",
                    detail=(
                        f"Binary '{clean_bin}' is not permitted by the active sandbox policy. "
                        f"Allowed binaries: {sorted(policy.allowed_binaries)}"
                    ),
                    is_security_violation=True,
                    context={"binary": clean_bin, "allowed": sorted(policy.allowed_binaries)},
                )
            )

        normalized_args: list[str] = []
        for idx, arg in enumerate(args):
            if "\x00" in arg:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_DANGEROUS_ARGUMENTS,
                        title="Null Byte In Command Argument",
                        detail=f"Argument at index {idx} contains an illegal null byte.",
                        is_security_violation=True,
                    )
                )
            normalized_args.append(normalize_nfc(arg))

        # Git-specific guardrails
        if clean_bin == "git":
            for arg in normalized_args:
                lower_arg = arg.lower()
                for bad_flag in _FORBIDDEN_GIT_FLAGS:
                    if bad_flag in lower_arg:
                        return Err(
                            DomainError(
                                code=ErrorCode.ERR_DANGEROUS_ARGUMENTS,
                                title="Restricted Git Flag Blocked",
                                detail=f"Git argument '{arg}' contains forbidden flag or config '{bad_flag}'.",
                                is_security_violation=True,
                                context={"binary": clean_bin, "blocked_argument": arg},
                            )
                        )
            non_flag_args = [a.lower() for a in normalized_args if not a.startswith("-")]
            if non_flag_args and non_flag_args[0] in _FORBIDDEN_GIT_SUBCOMMANDS:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_DANGEROUS_ARGUMENTS,
                        title="Restricted Git Subcommand Blocked",
                        detail=(
                            f"Git subcommand '{non_flag_args[0]}' is forbidden inside the sandbox "
                            "to prevent external network mutations or remote tampering."
                        ),
                        is_security_violation=True,
                        context={"binary": clean_bin, "subcommand": non_flag_args[0]},
                    )
                )

        return Ok((clean_bin, normalized_args))
