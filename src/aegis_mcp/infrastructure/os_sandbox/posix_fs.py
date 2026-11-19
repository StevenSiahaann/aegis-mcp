"""POSIX canonical path jail with O_NOFOLLOW, intermediate symlink walk, fstat S_ISREG, and atomic CAS writes."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import os
import re
import stat
from collections import deque
from pathlib import Path

from aegis_mcp.application.ports import (
    DirectoryEntryItem,
    DirectoryListResult,
    FilePatchResult,
    FileReadResult,
    FileWriteResult,
    SearchMatchItem,
    TextSearchResult,
)
from aegis_mcp.domain.errors import DomainError, ErrorCode
from aegis_mcp.domain.matchers import SecretRedactor, SensitiveFileMatcher, normalize_nfc
from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.domain.result import Err, Ok, Result
from aegis_mcp.domain.uuidv7 import generate_uuidv7

_SKIP_SEARCH_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".aegis-sandbox",
        "__pycache__",
        "node_modules",
        ".venv",
        "venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
    }
)

# Heuristic detector for catastrophic backtracking regexes:
# 1. Quantified group with inner quantifiers: (a+)+, (a*)*, ([a-z]+){2,}
# 2. Quantified group with alternation: (a|aa)+, (foo|foobar)*
# 3. Quantified nested groups: ((a)+)+
# 4. Backreferences: \1 .. \9
_REDOS_HAZARD_RE = re.compile(
    r"(?:\([^()]*[+*?{][^()]*\)\s*[+*?{])"
    r"|(?:\([^()]*\|[^()]*\)\s*[+*?{])"
    r"|(?:\((?:[^()]*\([^()]*\))+[^()]*\)\s*[+*?{])"
    r"|(?:\\[1-9])"
)


class PosixJailFileSystem:
    """Enforces OS-level directory jail invariants, sensitive file blocking, and atomic I/O."""

    def __init__(self, policy: SandboxPolicy) -> None:
        self._policy = policy
        self._root = policy.workspace_root

    def _to_rel_posix(self, path: Path) -> str:
        try:
            rel = path.relative_to(self._root)
            rel_str = rel.as_posix()
            return "." if rel_str == "" else rel_str
        except ValueError:
            return path.as_posix()

    def resolve_safe_path(
        self,
        rel_path: str,
        *,
        must_exist: bool = True,
        allow_directory: bool = False,
        check_sensitive: bool = True,
    ) -> Result[Path, DomainError]:
        """Validate and canonicalize a path inside the workspace root jail."""
        if "\x00" in rel_path:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_JAIL_ESCAPE,
                    title="Null Byte Injection Blocked",
                    detail="Path contains an illegal null byte.",
                    is_security_violation=True,
                )
            )

        clean_input = normalize_nfc(rel_path).strip()
        if not clean_input:
            clean_input = "."

        raw_path = Path(clean_input)
        if raw_path.is_absolute():
            # Allow absolute path only if it is already inside workspace_root
            try:
                raw_path = raw_path.relative_to(self._root)
            except ValueError:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_JAIL_ESCAPE,
                        title="Sandbox Boundary Violation",
                        detail="Requested absolute path escapes the workspace sandbox root.",
                        is_security_violation=True,
                        context={"requested_path": "<outside_workspace>"},
                    )
                )

        # Lexical traversal check & component-by-component walk from workspace_root
        current = self._root
        for part in raw_path.parts:
            norm_part = normalize_nfc(part)
            if norm_part in ("", "."):
                continue
            if norm_part == "..":
                if current == self._root:
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_JAIL_ESCAPE,
                            title="Sandbox Boundary Violation",
                            detail=f"Relative path '{clean_input}' attempts parent traversal outside workspace root.",
                            is_security_violation=True,
                            context={"requested_path": clean_input},
                        )
                    )
                current = current.parent
                continue

            next_candidate = current / norm_part
            if os.path.islink(next_candidate):
                if not self._policy.allow_symlinks_within_jail:
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_SYMLINK_BLOCKED,
                            title="Symlink Traversal Blocked",
                            detail=(
                                f"Path component '{norm_part}' in '{clean_input}' is a symbolic link, "
                                "which is forbidden by the active sandbox policy."
                            ),
                            is_security_violation=True,
                            context={"requested_path": clean_input, "symlink_component": norm_part},
                        )
                    )
                resolved_link = Path(os.path.realpath(next_candidate))
                if not resolved_link.is_relative_to(self._root):
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_JAIL_ESCAPE,
                            title="Symlink Escape Blocked",
                            detail=(
                                f"Symlink component '{norm_part}' in '{clean_input}' resolves outside "
                                "the workspace sandbox root."
                            ),
                            is_security_violation=True,
                            context={"requested_path": clean_input, "symlink_component": norm_part},
                        )
                    )
            current = next_candidate

        canonical_target = Path(os.path.realpath(current))
        if not canonical_target.is_relative_to(self._root):
            return Err(
                DomainError(
                    code=ErrorCode.ERR_JAIL_ESCAPE,
                    title="Sandbox Boundary Violation",
                    detail=f"Resolved path for '{clean_input}' escapes the workspace sandbox root.",
                    is_security_violation=True,
                    context={"requested_path": clean_input},
                )
            )

        rel_posix = self._to_rel_posix(canonical_target)
        if check_sensitive:
            is_sens, reason = SensitiveFileMatcher.is_sensitive(rel_posix)
            if is_sens:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_SENSITIVE_PATH_BLOCKED,
                        title="Restricted Credential or Sensitive File Blocked",
                        detail=f"Access to '{rel_posix}' is denied by sandbox policy: {reason}.",
                        is_security_violation=True,
                        context={"path": rel_posix, "reason": reason},
                    )
                )

        if must_exist and not os.path.lexists(current):
            return Err(
                DomainError(
                    code=ErrorCode.ERR_FILE_NOT_FOUND,
                    title="Path Not Found",
                    detail=f"Path '{rel_posix}' does not exist in workspace.",
                    context={"path": rel_posix},
                )
            )

        if must_exist and not allow_directory and canonical_target.is_dir():
            return Err(
                DomainError(
                    code=ErrorCode.ERR_IS_A_DIRECTORY,
                    title="Path Is A Directory",
                    detail=f"Expected a regular file at '{rel_posix}', but found a directory.",
                    context={"path": rel_posix},
                )
            )

        return Ok(current)

    def _read_regular_file_bytes(self, target_path: Path, rel_posix: str, max_size: int) -> Result[bytes, DomainError]:
        """Open file with O_NOFOLLOW | O_NONBLOCK, verify fstat S_ISREG, and read bytes safely."""
        flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(target_path), flags)
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_SYMLINK_BLOCKED,
                        title="Symlink Open Blocked (O_NOFOLLOW)",
                        detail=f"Kernel rejected opening '{rel_posix}' because it is a symbolic link.",
                        is_security_violation=True,
                        context={"path": rel_posix},
                    )
                )
            if exc.errno == errno.ENOENT:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_FILE_NOT_FOUND,
                        title="File Not Found",
                        detail=f"File '{rel_posix}' does not exist.",
                        context={"path": rel_posix},
                    )
                )
            if exc.errno == errno.EISDIR:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_IS_A_DIRECTORY,
                        title="Path Is A Directory",
                        detail=f"Path '{rel_posix}' is a directory.",
                        context={"path": rel_posix},
                    )
                )
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="File Open Error",
                    detail=f"Unable to open '{rel_posix}': {exc.strerror}",
                    context={"path": rel_posix},
                )
            )

        try:
            st = os.fstat(fd)
            if stat.S_ISDIR(st.st_mode):
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_IS_A_DIRECTORY,
                        title="Path Is A Directory",
                        detail=f"Expected a regular file at '{rel_posix}', but found a directory.",
                        context={"path": rel_posix},
                    )
                )
            if not stat.S_ISREG(st.st_mode):
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_SPECIAL_FILE_BLOCKED,
                        title="Special Device or FIFO Blocked",
                        detail=(
                            f"Path '{rel_posix}' is not a regular file (mode={oct(st.st_mode)}). "
                            "FIFOs, sockets, and device nodes are forbidden to prevent I/O hang attacks."
                        ),
                        is_security_violation=True,
                        context={"path": rel_posix, "mode": oct(st.st_mode)},
                    )
                )
            if st.st_nlink > 1 and not self._policy.allow_symlinks_within_jail:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_SPECIAL_FILE_BLOCKED,
                        title="Hardlinked File Blocked",
                        detail=(
                            f"Path '{rel_posix}' has multiple hardlinks (st_nlink={st.st_nlink}), "
                            "which is forbidden to prevent hardlink jail escapes."
                        ),
                        is_security_violation=True,
                        context={"path": rel_posix, "nlink": st.st_nlink},
                    )
                )
            if st.st_size > max_size:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_FILE_TOO_LARGE,
                        title="File Exceeds Maximum Size Limit",
                        detail=(
                            f"File '{rel_posix}' size ({st.st_size} bytes) exceeds maximum allowed limit "
                            f"({max_size} bytes)."
                        ),
                        context={"path": rel_posix, "size_bytes": st.st_size, "max_bytes": max_size},
                    )
                )

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    return Err(
                        DomainError(
                            code=ErrorCode.ERR_FILE_TOO_LARGE,
                            title="File Stream Exceeded Size Limit",
                            detail=f"Reading '{rel_posix}' exceeded {max_size} bytes.",
                            context={"path": rel_posix, "max_bytes": max_size},
                        )
                    )
                chunks.append(chunk)
            return Ok(b"".join(chunks))
        finally:
            os.close(fd)

    def read_text_file(
        self,
        rel_path: str,
        *,
        start_line: int = 1,
        end_line: int | None = None,
        max_bytes: int | None = None,
    ) -> Result[FileReadResult, DomainError]:
        path_res = self.resolve_safe_path(rel_path, must_exist=True, allow_directory=False)
        if path_res.is_err:
            return Err(path_res.unwrap_err())

        target_path = path_res.unwrap()
        rel_posix = self._to_rel_posix(target_path)
        hard_cap = max(self._policy.max_write_bytes, self._policy.max_read_bytes * 4)

        raw_res = self._read_regular_file_bytes(target_path, rel_posix, max_size=hard_cap)
        if raw_res.is_err:
            return Err(raw_res.unwrap_err())

        raw_bytes = raw_res.unwrap()
        if b"\x00" in raw_bytes[:8192]:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_BINARY_FILE,
                    title="Binary File Rejected",
                    detail=f"File '{rel_posix}' appears to be a binary file and cannot be read as UTF-8 text.",
                    context={"path": rel_posix},
                )
            )

        try:
            full_text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_BINARY_FILE,
                    title="Non-UTF8 File Rejected",
                    detail=f"File '{rel_posix}' is not valid UTF-8 text.",
                    context={"path": rel_posix},
                )
            )

        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        all_lines = full_text.splitlines()
        total_lines = len(all_lines)

        effective_end = total_lines if end_line is None else min(end_line, total_lines)
        if total_lines == 0:
            selected_lines: list[str] = []
            actual_start = 1
            actual_end = 0
        elif start_line > total_lines:
            selected_lines = []
            actual_start = start_line
            actual_end = total_lines
        else:
            selected_lines = all_lines[start_line - 1 : effective_end]
            actual_start = start_line
            actual_end = start_line - 1 + len(selected_lines)

        joined = "\n".join(selected_lines)
        byte_limit = max_bytes if max_bytes is not None else self._policy.max_read_bytes
        encoded_slice = joined.encode("utf-8")
        truncated = False
        if len(encoded_slice) > byte_limit:
            truncated = True
            joined = encoded_slice[:byte_limit].decode("utf-8", errors="ignore")
            joined += f"\n... [AEGIS SANDBOX: Output truncated at {byte_limit} bytes limit] ..."

        scrubbed_text, redaction_count = SecretRedactor.redact_text(joined)

        return Ok(
            FileReadResult(
                relative_path=rel_posix,
                content=scrubbed_text,
                sha256=file_sha256,
                total_bytes=len(raw_bytes),
                start_line=actual_start,
                end_line=actual_end,
                total_lines=total_lines,
                truncated=truncated,
                secrets_redacted=redaction_count,
            )
        )

    def _atomic_write_bytes(self, target_path: Path, data: bytes) -> Result[None, DomainError]:
        """Write bytes to a sibling temporary file with O_NOFOLLOW and atomically replace target."""
        parent_dir = target_path.parent
        # Verify or create parent directories inside the jail without crossing symlinks
        rel_parent = parent_dir.relative_to(self._root)
        curr = self._root
        for part in rel_parent.parts:
            curr = curr / part
            if os.path.islink(curr):
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_SYMLINK_BLOCKED,
                        title="Parent Directory Is A Symlink",
                        detail=f"Cannot write through symlinked parent directory '{curr.name}'.",
                        is_security_violation=True,
                    )
                )
            if not curr.exists():
                curr.mkdir(mode=0o755, exist_ok=True)

        if os.path.islink(target_path):
            return Err(
                DomainError(
                    code=ErrorCode.ERR_SYMLINK_BLOCKED,
                    title="Target File Is A Symlink",
                    detail=f"Refusing to overwrite symbolic link '{self._to_rel_posix(target_path)}'.",
                    is_security_violation=True,
                )
            )

        tmp_name = f".aegis_tmp_{generate_uuidv7().hex}"
        tmp_path = parent_dir / tmp_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(str(tmp_path), flags, 0o644)
            try:
                os.write(fd, data)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(str(tmp_path), str(target_path))
            return Ok(None)
        except OSError as exc:
            with contextlib.suppress(OSError):
                if os.path.lexists(tmp_path):
                    os.unlink(tmp_path)
            return Err(
                DomainError(
                    code=ErrorCode.ERR_VALIDATION_FAILED,
                    title="Atomic File Write Failed",
                    detail=f"Failed to atomically write '{self._to_rel_posix(target_path)}': {exc.strerror}",
                )
            )

    def write_text_file(
        self,
        rel_path: str,
        content: str,
        *,
        expected_sha256: str | None = None,
    ) -> Result[FileWriteResult, DomainError]:
        path_res = self.resolve_safe_path(rel_path, must_exist=False, allow_directory=False)
        if path_res.is_err:
            return Err(path_res.unwrap_err())

        target_path = path_res.unwrap()
        rel_posix = self._to_rel_posix(target_path)

        existed = os.path.lexists(target_path)
        previous_sha256: str | None = None
        existing_raw_bytes: bytes = b""

        if existed:
            existing_res = self._read_regular_file_bytes(
                target_path, rel_posix, max_size=self._policy.max_write_bytes * 2
            )
            if existing_res.is_err:
                return Err(existing_res.unwrap_err())
            existing_raw_bytes = existing_res.unwrap()
            previous_sha256 = hashlib.sha256(existing_raw_bytes).hexdigest()

        if expected_sha256 is not None:
            norm_expected = expected_sha256.strip().lower()
            if previous_sha256 is None or previous_sha256 != norm_expected:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_CAS_CONFLICT,
                        title="Optimistic Concurrency Control (SHA-256 CAS) Conflict",
                        detail=(
                            f"File '{rel_posix}' current SHA-256 ({previous_sha256!r}) does not match "
                            f"expected_sha256 ({norm_expected!r}). Re-read the file before writing."
                        ),
                        context={
                            "path": rel_posix,
                            "expected_sha256": norm_expected,
                            "actual_sha256": previous_sha256,
                        },
                    )
                )

        redacted_marker = SecretRedactor.find_redacted_placeholder(content)
        if redacted_marker is not None and redacted_marker.encode("utf-8") not in existing_raw_bytes:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_REDACTED_CONTENT_WRITE_BLOCKED,
                    title="Redacted Secret Placeholder Write Blocked",
                    detail=(
                        f"Content for '{rel_posix}' contains redaction placeholder '{redacted_marker}' "
                        "that was not present in the original file. Writing it back would overwrite "
                        "and destroy the real secret value. Use fs_patch_file on non-secret lines instead."
                    ),
                    context={"path": rel_posix, "placeholder": redacted_marker},
                )
            )

        new_bytes = content.encode("utf-8")
        new_sha256 = hashlib.sha256(new_bytes).hexdigest()

        write_res = self._atomic_write_bytes(target_path, new_bytes)
        if write_res.is_err:
            return Err(write_res.unwrap_err())

        return Ok(
            FileWriteResult(
                relative_path=rel_posix,
                bytes_written=len(new_bytes),
                previous_sha256=previous_sha256,
                new_sha256=new_sha256,
                created=not existed,
            )
        )

    def patch_text_file(
        self,
        rel_path: str,
        target: str,
        replacement: str,
        *,
        expected_sha256: str | None = None,
    ) -> Result[FilePatchResult, DomainError]:
        path_res = self.resolve_safe_path(rel_path, must_exist=True, allow_directory=False)
        if path_res.is_err:
            return Err(path_res.unwrap_err())

        target_path = path_res.unwrap()
        rel_posix = self._to_rel_posix(target_path)

        raw_res = self._read_regular_file_bytes(
            target_path, rel_posix, max_size=self._policy.max_write_bytes
        )
        if raw_res.is_err:
            return Err(raw_res.unwrap_err())

        raw_bytes = raw_res.unwrap()
        previous_sha256 = hashlib.sha256(raw_bytes).hexdigest()

        if expected_sha256 is not None:
            norm_expected = expected_sha256.strip().lower()
            if previous_sha256 != norm_expected:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_CAS_CONFLICT,
                        title="Optimistic Concurrency Control (SHA-256 CAS) Conflict",
                        detail=(
                            f"File '{rel_posix}' current SHA-256 ({previous_sha256}) does not match "
                            f"expected_sha256 ({norm_expected})."
                        ),
                        context={
                            "path": rel_posix,
                            "expected_sha256": norm_expected,
                            "actual_sha256": previous_sha256,
                        },
                    )
                )

        try:
            text = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_BINARY_FILE,
                    title="Non-UTF8 File Rejected",
                    detail=f"File '{rel_posix}' cannot be patched as UTF-8 text.",
                )
            )

        redacted_marker = SecretRedactor.find_redacted_placeholder(replacement)
        if redacted_marker is not None and redacted_marker not in text:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_REDACTED_CONTENT_WRITE_BLOCKED,
                    title="Redacted Secret Placeholder Patch Blocked",
                    detail=(
                        f"Patch replacement for '{rel_posix}' contains redaction placeholder "
                        f"'{redacted_marker}', which would destroy the original secret."
                    ),
                    context={"path": rel_posix, "placeholder": redacted_marker},
                )
            )

        occurrences = text.count(target)
        if occurrences == 0:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_PATCH_TARGET_NOT_FOUND,
                    title="Patch Target Block Not Found",
                    detail=f"The exact target string was not found in '{rel_posix}'.",
                    context={"path": rel_posix},
                )
            )
        if occurrences > 1:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_PATCH_AMBIGUOUS,
                    title="Ambiguous Patch Target Block",
                    detail=(
                        f"Target block matched {occurrences} locations in '{rel_posix}'. "
                        "Include more surrounding context lines to make the target unique."
                    ),
                    context={"path": rel_posix, "occurrences": occurrences},
                )
            )

        patched_text = text.replace(target, replacement, 1)
        new_bytes = patched_text.encode("utf-8")
        if len(new_bytes) > self._policy.max_write_bytes:
            return Err(
                DomainError(
                    code=ErrorCode.ERR_FILE_TOO_LARGE,
                    title="Patched File Exceeds Write Limit",
                    detail=f"Patched file size ({len(new_bytes)} bytes) exceeds max_write_bytes.",
                )
            )

        new_sha256 = hashlib.sha256(new_bytes).hexdigest()
        write_res = self._atomic_write_bytes(target_path, new_bytes)
        if write_res.is_err:
            return Err(write_res.unwrap_err())

        return Ok(
            FilePatchResult(
                relative_path=rel_posix,
                bytes_written=len(new_bytes),
                previous_sha256=previous_sha256,
                new_sha256=new_sha256,
            )
        )

    def list_directory(
        self,
        rel_path: str = ".",
        *,
        max_depth: int = 2,
        include_hidden: bool = False,
    ) -> Result[DirectoryListResult, DomainError]:
        path_res = self.resolve_safe_path(
            rel_path, must_exist=True, allow_directory=True, check_sensitive=True
        )
        if path_res.is_err:
            return Err(path_res.unwrap_err())

        start_dir = path_res.unwrap()
        if not start_dir.is_dir():
            return Err(
                DomainError(
                    code=ErrorCode.ERR_NOT_A_DIRECTORY,
                    title="Path Is Not A Directory",
                    detail=f"Path '{self._to_rel_posix(start_dir)}' is not a directory.",
                )
            )

        root_rel = self._to_rel_posix(start_dir)
        entries: list[DirectoryEntryItem] = []
        max_entries = 500
        truncated = False

        # Iterative BFS queue: (directory_path, current_depth)
        queue: deque[tuple[Path, int]] = deque([(start_dir, 1)])

        while queue:
            curr_dir, depth = queue.popleft()
            try:
                scandir_items = sorted(os.scandir(curr_dir), key=lambda e: e.name)
            except OSError:
                continue

            for entry in scandir_items:
                name_nfc = normalize_nfc(entry.name)
                if name_nfc == ".aegis-sandbox":
                    continue
                if not include_hidden and name_nfc.startswith("."):
                    # Still surface protected sensitive files like .env as protected notices if include_hidden=True
                    continue

                entry_path = curr_dir / name_nfc
                rel_entry = self._to_rel_posix(entry_path)

                if len(entries) >= max_entries:
                    truncated = True
                    break

                is_sens, _ = SensitiveFileMatcher.is_sensitive(rel_entry)
                if is_sens:
                    entries.append(
                        DirectoryEntryItem(
                            relative_path=rel_entry,
                            entry_type="protected_sensitive",
                            size_bytes=None,
                        )
                    )
                    continue

                if entry.is_symlink():
                    continue

                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue

                if stat.S_ISDIR(st.st_mode):
                    entries.append(
                        DirectoryEntryItem(
                            relative_path=rel_entry,
                            entry_type="directory",
                            size_bytes=None,
                        )
                    )
                    if depth < max_depth and name_nfc not in _SKIP_SEARCH_DIRS:
                        queue.append((entry_path, depth + 1))
                elif stat.S_ISREG(st.st_mode):
                    entries.append(
                        DirectoryEntryItem(
                            relative_path=rel_entry,
                            entry_type="file",
                            size_bytes=st.st_size,
                        )
                    )
            if truncated:
                break

        return Ok(
            DirectoryListResult(
                root_relative_path=root_rel,
                entries=tuple(entries),
                truncated=truncated,
            )
        )

    def search_text(
        self,
        query: str,
        *,
        rel_path: str = ".",
        is_regex: bool = False,
        max_results: int = 50,
    ) -> Result[TextSearchResult, DomainError]:
        path_res = self.resolve_safe_path(
            rel_path, must_exist=True, allow_directory=True, check_sensitive=True
        )
        if path_res.is_err:
            return Err(path_res.unwrap_err())

        start_node = path_res.unwrap()

        compiled_re: re.Pattern[str] | None = None
        if is_regex:
            if _REDOS_HAZARD_RE.search(query):
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_INVALID_REGEX,
                        title="Catastrophic Backtracking Regex Blocked (ReDoS Guard)",
                        detail="Regular expression contains nested quantifiers that pose a ReDoS risk.",
                        is_security_violation=True,
                        context={"query": query},
                    )
                )
            try:
                compiled_re = re.compile(query)
            except re.error as exc:
                return Err(
                    DomainError(
                        code=ErrorCode.ERR_INVALID_REGEX,
                        title="Invalid Regular Expression",
                        detail=f"Failed to compile regex '{query}': {exc}",
                        context={"query": query},
                    )
                )

        matches: list[SearchMatchItem] = []
        files_scanned = 0
        files_skipped_sensitive = 0
        total_redactions = 0
        truncated = False

        # Iterative traversal over directory tree
        file_queue: deque[Path] = deque()
        dir_queue: deque[tuple[Path, int]] = deque()

        if start_node.is_file():
            file_queue.append(start_node)
        else:
            dir_queue.append((start_node, 1))

        while dir_queue or file_queue:
            while file_queue:
                f_path = file_queue.popleft()
                rel_f = self._to_rel_posix(f_path)
                is_sens, _ = SensitiveFileMatcher.is_sensitive(rel_f)
                if is_sens:
                    files_skipped_sensitive += 1
                    continue

                raw_res = self._read_regular_file_bytes(
                    f_path, rel_f, max_size=self._policy.max_write_bytes
                )
                if raw_res.is_err:
                    continue
                raw_data = raw_res.unwrap()
                if b"\x00" in raw_data[:4096]:
                    continue
                try:
                    text = raw_data.decode("utf-8")
                except UnicodeDecodeError:
                    continue

                files_scanned += 1
                for line_idx, line in enumerate(text.splitlines(), start=1):
                    matched = (
                        bool(compiled_re.search(line))
                        if compiled_re is not None
                        else (query in line)
                    )
                    if matched:
                        scrubbed_line, r_count = SecretRedactor.redact_text(line[:500])
                        total_redactions += r_count
                        matches.append(
                            SearchMatchItem(
                                relative_path=rel_f,
                                line_number=line_idx,
                                line_text=scrubbed_line,
                            )
                        )
                        if len(matches) >= max_results:
                            truncated = True
                            break
                if truncated:
                    break

            if truncated or not dir_queue:
                break

            curr_dir, depth = dir_queue.popleft()
            try:
                scandir_items = sorted(os.scandir(curr_dir), key=lambda e: e.name)
            except OSError:
                continue

            for entry in scandir_items:
                name_nfc = normalize_nfc(entry.name)
                if name_nfc in _SKIP_SEARCH_DIRS or entry.is_symlink():
                    continue
                entry_path = curr_dir / name_nfc
                rel_entry = self._to_rel_posix(entry_path)
                is_sens, _ = SensitiveFileMatcher.is_sensitive(rel_entry)
                if is_sens:
                    files_skipped_sensitive += 1
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISDIR(st.st_mode) and depth < self._policy.max_dir_depth:
                    dir_queue.append((entry_path, depth + 1))
                elif stat.S_ISREG(st.st_mode):
                    file_queue.append(entry_path)

        return Ok(
            TextSearchResult(
                query=query,
                matches=tuple(matches),
                files_scanned=files_scanned,
                files_skipped_sensitive=files_skipped_sensitive,
                truncated=truncated,
                secrets_redacted=total_redactions,
            )
        )
