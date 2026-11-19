#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ==============================================================================
# AEGIS-MCP 5-GATE DETERMINISTIC VERIFICATION HARNESS
# ==============================================================================
# Enforces 100% compliance across secret scanning, architectural invariants,
# static linting (ruff), strict typechecking (mypy), and test coverage (pytest).
# ==============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0

if [[ -x ".venv/bin/python" ]]; then
    PY_BIN=".venv/bin/python"
else
    PY_BIN="python3"
fi

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}   AEGIS-MCP 5-GATE ARCHITECTURAL & SECURITY VERIFICATION HARNESS   ${NC}"
echo -e "${BLUE}====================================================================${NC}\n"

# GATE 1: SECRET & CREDENTIAL SCAN
echo -e "${YELLOW}[Gate 1/5] Scanning repository for hardcoded secrets...${NC}"
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    if git grep -I -E "AKIA[0-9A-Z]{16}|(ghp_|gho_|github_pat_)[a-zA-Z0-9_]{20,}|AIza[-0-9A-Za-z_]{35}|sk_live_[a-zA-Z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----" -- ':!scripts/verify.sh' >/dev/null 2>&1; then
        echo -e "${RED}[FAIL] Hardcoded secret pattern detected in git tracked files!${NC}"
        git grep -n -I -E "AKIA[0-9A-Z]{16}|(ghp_|gho_|github_pat_)[a-zA-Z0-9_]{20,}|AIza[-0-9A-Za-z_]{35}|sk_live_[a-zA-Z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----" -- ':!scripts/verify.sh'
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}[PASS] Zero hardcoded secrets detected.${NC}"
    fi
else
    echo -e "${YELLOW}[INFO] Git not initialized yet; scanning working tree directly...${NC}"
    if grep -r -I -E "AKIA[0-9A-Z]{16}|(ghp_|gho_|github_pat_)[a-zA-Z0-9_]{20,}|AIza[-0-9A-Za-z_]{35}|sk_live_[a-zA-Z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----" src tests examples >/dev/null 2>&1; then
        echo -e "${RED}[FAIL] Hardcoded secret pattern detected in source files!${NC}"
        ERRORS=$((ERRORS + 1))
    else
        echo -e "${GREEN}[PASS] Zero hardcoded secrets detected in working tree.${NC}"
    fi
fi

# GATE 2: ARCHITECTURAL & PROTOCOL INVARIANTS
echo -e "\n${YELLOW}[Gate 2/5] Verifying architectural & MCP protocol invariants...${NC}"
INV_FAIL=0

# 2a. Zero raw print() in src/ (stdout must be 100% pure JSON-RPC frames)
if grep -r -n -E "\bprint\s*\(" src/aegis_mcp >/dev/null 2>&1; then
    echo -e "${RED}[FAIL] Raw 'print()' detected in src/aegis_mcp! Stdout is reserved for JSON-RPC 2.0.${NC}"
    grep -r -n -E "\bprint\s*\(" src/aegis_mcp || true
    INV_FAIL=1
fi

# 2b. Zero shell=True in src/
if grep -r -n -E "shell\s*=\s*True" src/aegis_mcp >/dev/null 2>&1; then
    echo -e "${RED}[FAIL] 'shell=True' detected in src/aegis_mcp! Command execution must enforce shell=False.${NC}"
    grep -r -n -E "shell\s*=\s*True" src/aegis_mcp || true
    INV_FAIL=1
fi

# 2c. Verify AAA (# 1. ARRANGE, # 2. ACT, # 3. ASSERT) comments in all test files
for tf in tests/unit/*.py tests/integration/*.py tests/property/*.py tests/e2e/*.py; do
    if [[ -f "$tf" ]]; then
        if ! grep -q "# 1. ARRANGE" "$tf" || ! grep -q "# 2. ACT" "$tf" || ! grep -q "# 3. ASSERT" "$tf"; then
            echo -e "${RED}[FAIL] Test file '$tf' is missing mandatory '# 1. ARRANGE', '# 2. ACT', '# 3. ASSERT' blocks!${NC}"
            INV_FAIL=1
        fi
    fi
done

if [[ "$INV_FAIL" -eq 0 ]]; then
    echo -e "${GREEN}[PASS] All architectural invariants verified (Zero print(), zero shell=True, 100% AAA tests).${NC}"
else
    ERRORS=$((ERRORS + 1))
fi

# GATE 3: RUFF LINT & SYNTAX CHECK
echo -e "\n${YELLOW}[Gate 3/5] Running Ruff linter...${NC}"
if "$PY_BIN" -m ruff check src tests examples; then
    echo -e "${GREEN}[PASS] Ruff lint check passed with zero warnings.${NC}"
else
    echo -e "${RED}[FAIL] Ruff lint check failed!${NC}"
    ERRORS=$((ERRORS + 1))
fi

# GATE 4: MYPY STRICT STATIC TYPECHECK
echo -e "\n${YELLOW}[Gate 4/5] Running Mypy strict static typecheck...${NC}"
if "$PY_BIN" -m mypy --strict src tests examples; then
    echo -e "${GREEN}[PASS] Mypy strict typecheck passed (Zero type errors).${NC}"
else
    echo -e "${RED}[FAIL] Mypy strict typecheck failed!${NC}"
    ERRORS=$((ERRORS + 1))
fi

# GATE 5: AUTOMATED TEST SUITE & COVERAGE GATE
echo -e "\n${YELLOW}[Gate 5/5] Executing Pytest suite (Unit + Integration + Property + E2E)...${NC}"
if "$PY_BIN" -m pytest --cov=aegis_mcp --cov-branch --cov-report=term-missing --cov-fail-under=86; then
    echo -e "${GREEN}[PASS] All automated tests and coverage thresholds passed.${NC}"
else
    echo -e "${RED}[FAIL] Automated test suite or coverage threshold failed!${NC}"
    ERRORS=$((ERRORS + 1))
fi

echo -e "\n${BLUE}====================================================================${NC}"
if [[ "$ERRORS" -eq 0 ]]; then
    echo -e "${GREEN}   VERIFICATION HARNESS RESULT: ALL 5 GATES PASSED                  ${NC}"
    echo -e "${BLUE}====================================================================${NC}"
    exit 0
else
    echo -e "${RED}   VERIFICATION HARNESS RESULT: FAILED WITH $ERRORS ERROR(S)       ${NC}"
    echo -e "${BLUE}====================================================================${NC}"
    exit 1
fi
