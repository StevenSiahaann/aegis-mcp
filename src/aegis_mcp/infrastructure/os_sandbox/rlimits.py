"""Cross-platform POSIX resource limits (Linux & macOS Darwin) and optional macOS Seatbelt profile generator."""

from __future__ import annotations

import contextlib
import math
import resource
import sys
from collections.abc import Callable
from pathlib import Path

from aegis_mcp.domain.policy import SandboxPolicy
from aegis_mcp.infrastructure.os_sandbox.kernel_sandbox import SeatbeltDriver


def make_preexec_limiter(
    *,
    cpu_seconds: int,
    fsize_bytes: int,
    nofile: int,
    as_bytes: int = 536_870_912,
) -> Callable[[], None]:
    """Create a minimal, async-signal-safe preexec_fn callback for POSIX subprocesses.

    Handles macOS Darwin XNU kernel differences gracefully (where RLIMIT_AS/RLIMIT_NPROC
    behave differently from Linux) while enforcing deterministic RLIMIT_CPU, RLIMIT_FSIZE,
    RLIMIT_CORE, RLIMIT_NOFILE, and Linux RLIMIT_AS bounds.
    """
    safe_cpu = max(1, int(math.ceil(cpu_seconds)))
    safe_fsize = max(4096, int(fsize_bytes))
    safe_nofile = max(16, int(nofile))
    safe_as = max(33_554_432, int(as_bytes))

    def _apply_limits() -> None:
        # 1. Disable core dumps to prevent sensitive memory from being written to disk
        with contextlib.suppress(ValueError, OSError):
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

        # 2. Enforce hard CPU time limit (kernel delivers SIGXCPU then SIGKILL)
        with contextlib.suppress(ValueError, OSError):
            _, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)
            target_hard = safe_cpu + 1 if hard_cpu == resource.RLIM_INFINITY else min(safe_cpu + 1, hard_cpu)
            target_soft = min(safe_cpu, target_hard)
            resource.setrlimit(resource.RLIMIT_CPU, (target_soft, target_hard))

        # 3. Enforce maximum file size creation limit (kernel delivers SIGXFSZ / EFBIG)
        with contextlib.suppress(ValueError, OSError):
            _, hard_fsize = resource.getrlimit(resource.RLIMIT_FSIZE)
            target_fsize = safe_fsize if hard_fsize == resource.RLIM_INFINITY else min(safe_fsize, hard_fsize)
            resource.setrlimit(resource.RLIMIT_FSIZE, (target_fsize, target_fsize))

        # 4. Enforce open file descriptor limit
        with contextlib.suppress(ValueError, OSError):
            _, hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
            target_nofile = safe_nofile if hard_nofile == resource.RLIM_INFINITY else min(safe_nofile, hard_nofile)
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_nofile, target_nofile))

        # 5. Enforce virtual memory address space cap on Linux kernels
        if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
            with contextlib.suppress(ValueError, OSError):
                _, hard_as = resource.getrlimit(resource.RLIMIT_AS)
                target_as = safe_as if hard_as == resource.RLIM_INFINITY else min(safe_as, hard_as)
                resource.setrlimit(resource.RLIMIT_AS, (target_as, target_as))

    return _apply_limits


def build_macos_seatbelt_profile(workspace_root: Path, allow_write: bool) -> str:
    """Generate a deny-by-default macOS sandbox-exec SBPL profile."""
    policy = SandboxPolicy(workspace_root=workspace_root, allow_write=allow_write)
    driver = SeatbeltDriver(policy=policy, binary="/usr/bin/sandbox-exec")
    return driver.build_profile()
