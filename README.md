# `aegis-mcp` — Zero-SDK OS-Sandboxed Filesystem & Execution MCP Server

`aegis-mcp` is a raw **Model Context Protocol (MCP)** server engineered in pure Python (3.11+) that provides AI coding agents (**Claude Code**, **Google Antigravity**, **Cursor**, **OpenCode**, **Windsurf**) with deterministic **Filesystem** and **Code/Command Execution** capabilities inside a 5-layer OS security perimeter—**without requiring a Docker daemon or cloud micro-VM**.

---

## Why `aegis-mcp`?

Current open-source MCP servers fall into two extremes:
1. **Naive Host Filesystem Servers (`@modelcontextprotocol/server-filesystem`)**: Rely on simple string-prefix checks (`path.startsWith(root)`), leaving the host vulnerable to **intermediate directory symlink escapes**, **FIFO/device node read hangs**, **`.env` credential harvesting**, and **subprocess environment variable leakage (`os.environ`)**.
2. **Heavy Container Sandboxes (`docker run` MCP wrappers)**: Incur 1,500–3,000ms cold-start latency per tool invocation, consume gigabytes of background VM memory, and fail in Dockerless environments.

`aegis-mcp` delivers **< 10ms local execution latency** while enforcing strict kernel and OS-level security invariants.

---

## The 5-Layer OS Security Perimeter

| Layer | Security Invariant | Threat Mitigated |
| :--- | :--- | :--- |
| **Layer 1: Canonical Path Jail** | Component-by-component directory walk from `workspace_root`, `os.path.realpath()` boundary verification, `O_NOFOLLOW \| O_NONBLOCK` descriptor opens, and `fstat(fd)` `S_ISREG` verification. | Blocks `../../` path traversal, intermediate directory symlink escapes (`CWE-59`), TOCTOU swaps (`CWE-367`), and `/dev/zero` or named pipe (`mkfifo`) hang attacks (`CWE-400`). |
| **Layer 2: Sensitive File Denylist** | Unicode `NFC` normalization + automatic rejection of `.env*` (while allowing `.env.example`), `*.pem`, `*.key`, `id_rsa*`, `.git/config`, `.git/credentials`, `.npmrc`, `*.tfstate*`, and cloud service-account keys. | Blocks silent credential harvesting (`OWASP LLM06`) even when secret files reside physically inside the workspace root. |
| **Layer 3: Zero-Trust Env Scrubbing** | Subprocesses never inherit `os.environ`. A clean-room environment is constructed with safe `PATH`, `LANG=en_US.UTF-8`, and `HOME`/`TMPDIR` redirected to `.aegis-sandbox/tmp` inside the jail. | Prevents malicious or injected LLM scripts (`import os; print(os.environ)`) from stealing host `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, or AWS keys (`CWE-526`). |
| **Layer 4: Kernel Resource Limits & Process-Group Watchdog** | Subprocesses run in an isolated session (`start_new_session=True` / `setsid`) with POSIX `setrlimit` (`RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CORE=0`), non-blocking `selectors.DefaultSelector` dual-pipe draining, and monotonic `os.killpg(pgid, SIGKILL)` on timeout. | Eliminates 64KB OS pipe buffer deadlocks, infinite loops, disk-filling bombs, and orphan grandchild processes. Optional macOS `sandbox-exec` (Seatbelt) kernel profile (`--enable-seatbelt`). |
| **Layer 5: Bounded Output & Egress Secret Redactor** | Caps `stdout`/`stderr` and file reads at `64 KB` ($O(1)$ bounded memory) and scrubs inline high-entropy credentials (AWS `AKIA...`, GitHub `ghp_...`, OpenAI/Anthropic `sk-...`, Google `AIza...`, Bearer tokens, PEM private keys) prior to JSON-RPC serialization. | Prevents context-window flooding and accidental secret leakage into external LLM provider logs. |

---

## Clean Architecture & Zero-SDK Protocol Design

`aegis-mcp` implements the **Model Context Protocol (`2024-11-05` & `2025-03-26`)** over newline-delimited JSON-RPC 2.0 `stdio` from scratch without the `mcp` or `FastMCP` SDKs:

- **Domain Layer (`src/aegis_mcp/domain/`)**: Pure functional `Result[T, DomainError]` monad, **RFC 7807 Problem Details** error serialization, **RFC 9562 UUIDv7** generator, Unicode `NFC` normalizer, `SensitiveFileMatcher`, `SecretRedactor`, and `CommandArgumentGuard`.
- **Application Layer (`src/aegis_mcp/application/`)**: Single-responsibility Use-Case Handlers (`ReadFileHandler`, `ListDirectoryHandler`, `SearchTextHandler`, `WriteFileHandler`, `PatchFileHandler`, `RunPythonHandler`, `RunCommandHandler`, `InspectPolicyHandler`) with **SHA-256 Optimistic Concurrency Control (CAS)** and **LRU Idempotency-Key Replay Protection**.
- **Infrastructure Layer (`src/aegis_mcp/infrastructure/`)**: `PosixJailFileSystem`, `SelectorSandboxRunner`, W3C `traceparent` propagation via `contextvars.ContextVar`, **Single-Line NDJSON** structured logging on `stderr` with recursive PII/Secret scrubbing, and RED latency telemetry ($p50, p95, p99$).

---

## Exposed MCP Tools

| Tool Name | Mode | Description |
| :--- | :--- | :--- |
| `fs_read_file` | Read-Only | Read UTF-8 text files with line range (`start_line`, `end_line`), byte cap, SHA-256 digest, and inline secret redaction. |
| `fs_list_directory` | Read-Only | Iterative BFS directory listing (`max_depth <= 10`). Sensitive files are flagged as `protected_sensitive`. |
| `fs_search_text` | Read-Only | Streaming literal/regex search across workspace files with ReDoS protection and automatic binary/secret skipping. |
| `fs_write_file` | `--allow-write` | Atomic file creation/update via `O_NOFOLLOW` temp-file swap (`.aegis_tmp_<uuidv7>` + `os.replace`), optional `expected_sha256` CAS, and `idempotency_key`. |
| `fs_patch_file` | `--allow-write` | Atomic exact-block replacement (`target` $\rightarrow$ `replacement`) with `expected_sha256` CAS and `idempotency_key`. |
| `exec_python` | `--allow-exec` | Execute isolated Python code inside the workspace with clean-room environment, POSIX `rlimit`, and process-group timeout `SIGKILL`. |
| `exec_command` | `--allow-exec` | Execute allowlisted binaries (`pytest`, `ruff`, `mypy`, `git`, `ls`, `wc`, `head`, `tail`, `python3`) with `shell=False` and dangerous git flag blocking. |
| `sandbox_inspect_policy` | Diagnostic | Return active sandbox configuration, resource limits, allowed binaries, and live RED telemetry metrics. |

---

## Quickstart & Installation

```bash
cd /Users/71234/explore-opensource/aegis-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run the 8-Vector Adversarial Security Benchmark

```bash
python3 examples/demo_attack_simulation.py
```

### Run the 5-Gate Verification Harness

```bash
chmod +x scripts/verify.sh
./scripts/verify.sh
```

---

## MCP Client Configuration (Claude Code / Antigravity / Cursor / OpenCode)

Add `aegis-mcp` to your MCP client configuration (`claude_desktop_config.json`, `.cursor/mcp.json`, or Antigravity MCP settings):

```json
{
  "mcpServers": {
    "aegis-sandbox": {
      "command": "python3",
      "args": [
        "-m",
        "aegis_mcp",
        "--root",
        "/absolute/path/to/your/project",
        "--allow-write",
        "--allow-exec",
        "--wrap-untrusted",
        "--timeout",
        "5.0"
      ]
    }
  }
}
```

For strict read-only auditing mode (Least Privilege default), omit `--allow-write` and `--allow-exec`.

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).

