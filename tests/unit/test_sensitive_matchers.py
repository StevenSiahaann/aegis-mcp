"""Unit tests for SensitiveFileMatcher, Unicode NFC normalization, and SecretRedactor."""

from __future__ import annotations

import unicodedata

import pytest

from aegis_mcp.domain.matchers import SecretRedactor, SensitiveFileMatcher


@pytest.mark.parametrize(
    "blocked_path",
    [
        ".env",
        ".env.local",
        ".env.production",
        "config/.env.staging",
        "secrets/server.pem",
        "tls/private.key",
        "certs/keystore.p12",
        "id_rsa",
        "keys/id_ed25519",
        ".git/config",
        ".git/credentials",
        ".aws/credentials",
        ".npmrc",
        ".pypirc",
        "gcp-service-account-prod.json",
        "infra/terraform.tfstate",
        "infra/prod.tfvars",
    ],
)
def test_sensitive_file_matcher_blocks_restricted_files(blocked_path: str) -> None:
    # 1. ARRANGE
    target = blocked_path

    # 2. ACT
    is_blocked, reason = SensitiveFileMatcher.is_sensitive(target)

    # 3. ASSERT
    assert is_blocked is True
    assert len(reason) > 0


@pytest.mark.parametrize(
    "safe_path",
    [
        ".env.example",
        ".env.template",
        ".env.sample",
        "src/main.py",
        "README.md",
        "tests/test_auth.py",
        "docs/architecture.md",
        "pyproject.toml",
    ],
)
def test_sensitive_file_matcher_allows_safe_files_and_templates(safe_path: str) -> None:
    # 1. ARRANGE
    target = safe_path

    # 2. ACT
    is_blocked, reason = SensitiveFileMatcher.is_sensitive(target)

    # 3. ASSERT
    assert is_blocked is False
    assert reason == ""


def test_sensitive_file_matcher_normalizes_nfd_unicode() -> None:
    # 1. ARRANGE
    nfd_path = unicodedata.normalize("NFD", "café/.env.local")

    # 2. ACT
    is_blocked, _ = SensitiveFileMatcher.is_sensitive(nfd_path)

    # 3. ASSERT
    assert is_blocked is True


def test_secret_redactor_scrubs_inline_credentials_and_nested_dicts() -> None:
    # 1. ARRANGE
    # Construct synthetic test tokens at runtime so static git-grep secret scanners stay clean
    fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    fake_gh = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD"
    fake_openai = "sk-proj-" + "1234567890abcdefghijklmnopqrstuvwxyz"
    fake_pem = (
        "-----BEGIN RSA "
        + "PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA "
        + "PRIVATE KEY-----"
    )
    raw_text = (
        f"AWS={fake_aws}\n"
        f"GH={fake_gh}\n"
        f"OPENAI={fake_openai}\n"
        f"Authorization: Bearer super_secret_jwt_value_12345\n"
        f"DB_PASSWORD='my_ultra_secret_password_99'\n"
        f"{fake_pem}"
    )
    nested_log = {
        "user": "alice",
        "api_key": "raw_key_value",
        "nested": {
            "client_secret": "top_secret",
            "stdout_preview": f"Token is {fake_gh}",
        },
    }

    # 2. ACT
    scrubbed_text, count = SecretRedactor.redact_text(raw_text)
    scrubbed_dict = SecretRedactor.redact_structure(nested_log)

    # 3. ASSERT
    assert count >= 6
    assert fake_aws not in scrubbed_text
    assert fake_gh not in scrubbed_text
    assert fake_openai not in scrubbed_text
    assert "super_secret_jwt_value_12345" not in scrubbed_text
    assert "my_ultra_secret_password_99" not in scrubbed_text
    assert "[REDACTED_AWS_KEY]" in scrubbed_text
    assert "[REDACTED_GITHUB_TOKEN]" in scrubbed_text
    assert "[REDACTED_API_KEY]" in scrubbed_text
    assert "[REDACTED_PEM_PRIVATE_KEY]" in scrubbed_text
    assert scrubbed_dict["api_key"] == "[REDACTED]"
    assert scrubbed_dict["nested"]["client_secret"] == "[REDACTED]"
    assert fake_gh not in scrubbed_dict["nested"]["stdout_preview"]

