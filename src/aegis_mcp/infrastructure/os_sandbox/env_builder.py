"""Zero-trust subprocess environment constructor that strips host secrets and isolates HOME/TMPDIR."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

from aegis_mcp.domain.matchers import SecretRedactor
from aegis_mcp.domain.policy import SandboxPolicy

_FORBIDDEN_ENV_KEY_RE = re.compile(
    r"(?:KEY|TOKEN|SECRET|PASSWORD|PASS|CREDENTIAL|AUTH|PRIVATE|DSN|CONN|"
    r"AWS_|GCP_|GOOGLE_|AZURE_|OPENAI_|ANTHROPIC_|GITHUB_|GITLAB_|SLACK_|STRIPE_|"
    r"LD_PRELOAD|LD_LIBRARY_PATH|DYLD_|PYTHONSTARTUP|PYTHONINSPECT|PYTHONPATH|BASH_ENV|ENV)",
    re.IGNORECASE,
)

_STANDARD_SAFE_PATHS: tuple[str, ...] = (
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/opt/homebrew/bin",
)


class CleanEnvironmentBuilder:
    """Constructs a minimal, secret-free environment dictionary for sandboxed child processes."""

    @staticmethod
    def build(policy: SandboxPolicy, extra_env: dict[str, str] | None = None) -> dict[str, str]:
        """Build a clean-room environment dictionary without inheriting os.environ secrets."""
        scratch_dir = policy.sandbox_scratch_dir
        scratch_dir.mkdir(parents=True, exist_ok=True)

        # Include current Python interpreter's bin directory so tools like pytest/ruff in the active venv work
        py_bin_dir = str(Path(sys.executable).resolve().parent)
        path_entries: list[str] = [py_bin_dir]
        for std_p in _STANDARD_SAFE_PATHS:
            if std_p not in path_entries and os.path.isdir(std_p):
                path_entries.append(std_p)

        clean_env: dict[str, str] = {
            "PATH": os.pathsep.join(path_entries),
            "LANG": "en_US.UTF-8",
            "LC_ALL": "en_US.UTF-8",
            "HOME": str(scratch_dir),
            "TMPDIR": str(scratch_dir),
            "TMP": str(scratch_dir),
            "TEMP": str(scratch_dir),
            "XDG_CACHE_HOME": str(scratch_dir / ".cache"),
            "XDG_CONFIG_HOME": str(scratch_dir / ".config"),
            "PYTHONPATH": str(policy.workspace_root),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONUNBUFFERED": "1",
            "PYTHONNOUSERSITE": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "TERM": "dumb",
        }

        if extra_env:
            for k, v in extra_env.items():
                if not k or "\x00" in k or "\x00" in v:
                    continue
                if _FORBIDDEN_ENV_KEY_RE.search(k):
                    continue
                _, redaction_count = SecretRedactor.redact_text(v)
                if redaction_count > 0:
                    continue
                clean_env[k] = v

        return clean_env
