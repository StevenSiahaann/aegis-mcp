"""Property-based fuzzing tests using Hypothesis to prove zero sandbox escape and secret scrubbing."""

from __future__ import annotations

import tempfile
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis_mcp.domain.matchers import SecretRedactor
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem

_adversarial_path_strategy = st.lists(
    st.sampled_from(
        [
            "..",
            ".",
            "/",
            "\\",
            "\x00",
            ".env",
            ".env.local",
            ".git/config",
            "id_rsa",
            "key.pem",
            "src",
            "nested",
            "file.txt",
            "caf\u00e9",
            "cafe\u0301",
            "~",
            "etc",
            "passwd",
        ]
    ),
    min_size=1,
    max_size=8,
).map(lambda parts: "/".join(parts))


@settings(max_examples=150, deadline=None)
@given(candidate_path=_adversarial_path_strategy)
def test_property_resolve_safe_path_never_escapes_workspace_root(candidate_path: str) -> None:
    # 1. ARRANGE
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir).resolve()
        policy = SandboxPolicy(workspace_root=root)
        fs = PosixJailFileSystem(policy)

        # 2. ACT
        result = fs.resolve_safe_path(
            candidate_path,
            must_exist=False,
            allow_directory=True,
            check_sensitive=True,
        )

        # 3. ASSERT
        if result.is_ok:
            resolved = result.unwrap().resolve()
            assert resolved.is_relative_to(root)


@settings(max_examples=100, deadline=None)
@given(
    prefix=st.text(min_size=0, max_size=40),
    suffix=st.text(
        alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        min_size=24,
        max_size=40,
    ),
    trailing=st.text(min_size=0, max_size=40),
)
def test_property_secret_redactor_always_masks_github_pat_tokens(
    prefix: str,
    suffix: str,
    trailing: str,
) -> None:
    # 1. ARRANGE
    synthetic_token = "ghp_" + suffix
    text = f"{prefix} {synthetic_token} {trailing}"

    # 2. ACT
    scrubbed, count = SecretRedactor.redact_text(text)

    # 3. ASSERT
    assert count >= 1
    assert synthetic_token not in scrubbed
    assert "[REDACTED_GITHUB_TOKEN]" in scrubbed

