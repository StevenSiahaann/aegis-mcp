"""Integration tests for PosixJailFileSystem against real OS symlinks, FIFOs, and CAS writes."""

from __future__ import annotations

import os
from pathlib import Path

from aegis_mcp.domain.errors import ErrorCode
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.os_sandbox.posix_fs import PosixJailFileSystem


def test_blocks_direct_and_intermediate_directory_symlink_escapes(tmp_path: Path) -> None:
    # 1. ARRANGE
    workspace = tmp_path / "workspace"
    outside = tmp_path / "outside_secrets"
    workspace.mkdir()
    outside.mkdir()
    secret_file = outside / "master_key.txt"
    secret_file.write_text("TOP_SECRET_OUTSIDE_VALUE", encoding="utf-8")

    # Direct file symlink escape
    os.symlink(secret_file, workspace / "innocent_notes.txt")
    # Intermediate directory symlink escape
    os.symlink(outside, workspace / "docs_link")

    policy_strict = SandboxPolicy(
        workspace_root=workspace,
        allow_symlinks_within_jail=False,
    )
    policy_jail_symlinks = SandboxPolicy(
        workspace_root=workspace,
        allow_symlinks_within_jail=True,
    )
    fs_strict = PosixJailFileSystem(policy_strict)
    fs_jail_links = PosixJailFileSystem(policy_jail_symlinks)

    # 2. ACT
    res_direct_strict = fs_strict.read_text_file("innocent_notes.txt")
    res_dir_strict = fs_strict.read_text_file("docs_link/master_key.txt")
    res_direct_escape = fs_jail_links.read_text_file("innocent_notes.txt")
    res_dir_escape = fs_jail_links.read_text_file("docs_link/master_key.txt")

    # 3. ASSERT
    assert res_direct_strict.is_err is True
    assert res_direct_strict.unwrap_err().code == ErrorCode.ERR_SYMLINK_BLOCKED
    assert res_dir_strict.is_err is True
    assert res_dir_strict.unwrap_err().code == ErrorCode.ERR_SYMLINK_BLOCKED

    assert res_direct_escape.is_err is True
    assert res_direct_escape.unwrap_err().code == ErrorCode.ERR_JAIL_ESCAPE
    assert res_dir_escape.is_err is True
    assert res_dir_escape.unwrap_err().code == ErrorCode.ERR_JAIL_ESCAPE


def test_blocks_named_pipe_fifo_without_hanging(tmp_path: Path) -> None:
    # 1. ARRANGE
    fifo_path = tmp_path / "trap_pipe.fifo"
    os.mkfifo(fifo_path)
    policy = SandboxPolicy(workspace_root=tmp_path)
    fs = PosixJailFileSystem(policy)

    # 2. ACT
    result = fs.read_text_file("trap_pipe.fifo")

    # 3. ASSERT
    assert result.is_err is True
    assert result.unwrap_err().code == ErrorCode.ERR_SPECIAL_FILE_BLOCKED
    assert result.unwrap_err().is_security_violation is True


def test_atomic_write_and_patch_with_optimistic_concurrency_cas(tmp_path: Path) -> None:
    # 1. ARRANGE
    policy = SandboxPolicy(workspace_root=tmp_path, allow_write=True)
    fs = PosixJailFileSystem(policy)

    # 2. ACT
    create_res = fs.write_text_file("src/service.py", "def compute():\n    return 10\n")
    first_sha = create_res.unwrap().new_sha256

    # CAS mismatch attempt
    stale_write_res = fs.write_text_file(
        "src/service.py",
        "def compute():\n    return 99\n",
        expected_sha256="0" * 64,
    )

    # Valid CAS patch
    patch_res = fs.patch_text_file(
        "src/service.py",
        target="return 10",
        replacement="return 42",
        expected_sha256=first_sha,
    )
    read_after = fs.read_text_file("src/service.py")

    # 3. ASSERT
    assert create_res.is_ok is True
    assert create_res.unwrap().created is True
    assert stale_write_res.is_err is True
    assert stale_write_res.unwrap_err().code == ErrorCode.ERR_CAS_CONFLICT
    assert patch_res.is_ok is True
    assert read_after.is_ok is True
    assert "return 42" in read_after.unwrap().content
    assert read_after.unwrap().sha256 == patch_res.unwrap().new_sha256


def test_directory_list_and_search_skip_sensitive_files_and_guard_redos(tmp_path: Path) -> None:
    # 1. ARRANGE
    (tmp_path / ".env").write_text("SECRET_KEY=super_secret_val_123", encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "# Normal code\nAPI_TOKEN = 'ghp_" + "1234567890abcdefghijklmnopqrstuvwxyzABCD'\n",
        encoding="utf-8",
    )
    policy = SandboxPolicy(workspace_root=tmp_path)
    fs = PosixJailFileSystem(policy)

    # 2. ACT
    list_res = fs.list_directory(".", include_hidden=True)
    search_res = fs.search_text("API_TOKEN", rel_path=".")
    redos_res = fs.search_text("(a+)+$", rel_path=".", is_regex=True)

    # 3. ASSERT
    assert list_res.is_ok is True
    entries_by_path = {e.relative_path: e.entry_type for e in list_res.unwrap().entries}
    assert entries_by_path[".env"] == "protected_sensitive"
    assert entries_by_path["app.py"] == "file"

    assert search_res.is_ok is True
    search_dto = search_res.unwrap()
    assert search_dto.files_skipped_sensitive >= 1
    assert len(search_dto.matches) == 1
    assert "[REDACTED_GITHUB_TOKEN]" in search_dto.matches[0].line_text

    assert redos_res.is_err is True
    assert redos_res.unwrap_err().code == ErrorCode.ERR_INVALID_REGEX

