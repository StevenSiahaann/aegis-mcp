"""Unicode NFC normalization, sensitive file denylist matching, secret redaction, and command argument guards."""

from __future__ import annotations

import fnmatch
import os
import re
import unicodedata
from pathlib import Path
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
        ".envrc",
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
    ".ovpn",
)

_SENSITIVE_GLOBS: tuple[str, ...] = (
    ".env.*",
    ".envrc.*",
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
    ".git/hooks",
    ".git/hooks/*",
    ".git-credentials",
    ".aws/credentials",
    ".aws/config",
    ".docker/config.json",
    ".kube/config",
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
    # Raw JSON Web Tokens (JWT - 3 base64url segments starting with eyJ)
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        "[REDACTED_JWT_TOKEN]",
    ),
    # Database and Basic-Auth Connection URIs (postgresql://user:pass@host, redis://:pass@host, etc.)
    (
        re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqp(?:s)?|https?|ftp)://[^:\s/'\"]*:)(?!\[REDACTED_)([^@\s'\"]+)(@)"
        ),
        r"\1[REDACTED_URI_PASSWORD]\3",
    ),
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


_REDACTED_MARKER_RE = re.compile(
    r"\[REDACTED_(?:SECRET|AWS_KEY|GITHUB_TOKEN|API_KEY|GOOGLE_API_KEY|SLACK_TOKEN|AUTH_TOKEN|PEM_PRIVATE_KEY|JWT_TOKEN|URI_PASSWORD)\]"
)


class SecretRedactor:
    """Scrubs Tier-3/Tier-4 secrets from text outputs and structured log dictionaries."""

    @staticmethod
    def find_redacted_placeholder(text: str) -> str | None:
        """Return the first [REDACTED_*] placeholder found in text, or None."""
        match = _REDACTED_MARKER_RE.search(text)
        return match.group(0) if match else None

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
        "gc",
        "archive",
        "bundle",
        "submodule",
        "worktree",
    }
)

_FORBIDDEN_GIT_FLAGS: tuple[str, ...] = (
    "--global",
    "--system",
    "--upload-pack",
    "--receive-pack",
    "--exec",
    "--no-index",
    "--git-dir",
    "--work-tree",
    "--output",
    "core.sshcommand",
    "core.fsmonitor",
    "core.editor",
    "core.hooksPath",
    "alias.",
    "--force",
)

_FORBIDDEN_GIT_EXACT_FLAGS: frozenset[str] = frozenset({"-c", "-C", "-f"})


class CommandArgumentGuard:
    """Validates binary allowlist and prevents dangerous subcommands, flag injections, or path escapes."""

    @staticmethod
    def _check_arg_path_safety(arg: str, policy: SandboxPolicy) -> DomainError | None:
        """Ensure command arguments cannot reference paths outside the workspace jail or sensitive files."""
        candidates = [arg]
        if "=" in arg and arg.startswith("-"):
            _, val = arg.split("=", 1)
            if val:
                candidates.append(val)
        elif (
            len(arg) > 2
            and arg.startswith("-")
            and not arg.startswith("--")
            and ("/" in arg[2:] or "\\" in arg[2:] or "~" in arg[2:] or ".." in arg[2:])
        ):
            candidates.append(arg[2:])

        for token in candidates:
            clean = token.strip()
            if not clean:
                continue
            if clean.startswith("~"):
                return DomainError(
                    code=ErrorCode.ERR_JAIL_ESCAPE,
                    title="Home Directory Expansion Blocked In Command Argument",
                    detail=f"Argument '{arg}' references '~' outside the workspace sandbox.",
                    is_security_violation=True,
                )
            norm_parts = clean.replace("\\", "/").split("/")
            if ".." in norm_parts:
                return DomainError(
                    code=ErrorCode.ERR_JAIL_ESCAPE,
                    title="Parent Traversal Blocked In Command Argument",
                    detail=f"Argument '{arg}' contains '..' path traversal.",
                    is_security_violation=True,
                )
            if clean.startswith("/"):
                resolved = Path(os.path.realpath(clean))
                if not resolved.is_relative_to(policy.workspace_root):
                    return DomainError(
                        code=ErrorCode.ERR_JAIL_ESCAPE,
                        title="Outside-Workspace Path Blocked In Command Argument",
                        detail=f"Argument '{arg}' references an absolute path outside the workspace sandbox.",
                        is_security_violation=True,
                    )
                rel_posix = resolved.relative_to(policy.workspace_root).as_posix()
                is_sens, reason = SensitiveFileMatcher.is_sensitive(rel_posix)
                if is_sens:
                    return DomainError(
                        code=ErrorCode.ERR_SENSITIVE_PATH_BLOCKED,
                        title="Sensitive File Blocked In Command Argument",
                        detail=f"Argument '{arg}' targets a protected file: {reason}.",
                        is_security_violation=True,
                    )
            elif not clean.startswith("-"):
                is_sens, reason = SensitiveFileMatcher.is_sensitive(clean)
                if is_sens:
                    return DomainError(
                        code=ErrorCode.ERR_SENSITIVE_PATH_BLOCKED,
                        title="Sensitive File Blocked In Command Argument",
                        detail=f"Argument '{arg}' targets a protected file: {reason}.",
                        is_security_violation=True,
                    )
                # Walk components to check for symlinks and resolved target sensitivity
                curr = policy.workspace_root
                for part in Path(clean).parts:
                    if part in ("", "."):
                        continue
                    curr = curr / part
                    if os.path.islink(curr) and not policy.allow_symlinks_within_jail:
                        return DomainError(
                            code=ErrorCode.ERR_SYMLINK_BLOCKED,
                            title="Symlink Argument Blocked",
                            detail=f"Argument '{arg}' traverses symbolic link '{part}', which is forbidden.",
                            is_security_violation=True,
                        )
                candidate_path = policy.workspace_root / clean
                if os.path.lexists(candidate_path):
                    resolved = Path(os.path.realpath(candidate_path))
                    if not resolved.is_relative_to(policy.workspace_root):
                        return DomainError(
                            code=ErrorCode.ERR_JAIL_ESCAPE,
                            title="Symlink Escape Blocked In Command Argument",
                            detail=f"Argument '{arg}' resolves outside the workspace sandbox.",
                            is_security_violation=True,
                        )
                    resolved_rel = resolved.relative_to(policy.workspace_root).as_posix()
                    is_sens_target, target_reason = SensitiveFileMatcher.is_sensitive(resolved_rel)
                    if is_sens_target:
                        return DomainError(
                            code=ErrorCode.ERR_SENSITIVE_PATH_BLOCKED,
                            title="Symlink To Sensitive File Blocked In Command Argument",
                            detail=f"Argument '{arg}' resolves to protected file: {target_reason}.",
                            is_security_violation=True,
                        )
        return None

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
            norm_arg = normalize_nfc(arg)
            path_err = CommandArgumentGuard._check_arg_path_safety(norm_arg, policy)
            if path_err is not None:
                return Err(path_err)
            normalized_args.append(norm_arg)

        # Git-specific guardrails
        if clean_bin == "git":
            for arg in normalized_args:
                if (
                    arg in _FORBIDDEN_GIT_EXACT_FLAGS
                    or (arg.startswith("-C") and len(arg) > 2)
                    or (arg.startswith("-c") and len(arg) > 2)
                ):
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_DANGEROUS_ARGUMENTS,
                            title="Restricted Git Flag Blocked",
                            detail=f"Git flag '{arg}' is forbidden inside the sandbox.",
                            is_security_violation=True,
                            context={"binary": clean_bin, "blocked_argument": arg},
                        )
                    )
                lower_arg = arg.lower()
                for bad_flag in _FORBIDDEN_GIT_FLAGS:
                    if bad_flag.lower() in lower_arg:
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
