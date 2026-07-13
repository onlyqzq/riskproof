#!/usr/bin/env bash
# ============================================================================
# RiskProof Test Workspace — Quick Smoke Test
# ============================================================================
# 快速冒烟测试，验证核心流程可用。运行时间 < 5秒。
# 用法: bash test-workspace/scripts/quick-smoke.sh
# ============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
WORKSPACE_DIR="$PROJECT_DIR/test-workspace"
CLI_ENTRY="$PROJECT_DIR/packages/riskproof/src/cli.ts"
PASS=0
FAIL=0
TEMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/riskproof-quick-smoke.XXXXXX")"
trap 'rm -rf "$TEMP_DIR"' EXIT

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}${CYAN}  RiskProof — Quick Smoke Test${NC}"
echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════${NC}"
echo ""

check() {
  local name="$1"
  local file="$2"
  local expected_exit="$3"
  local expected_label="$4"
  local event_file="$TEMP_DIR/event-$((PASS+FAIL+1)).json"

  # Scenario files include a human-readable `scenario` wrapper used by the
  # test harness. The production CLI intentionally rejects unknown engine
  # fields, so pass only the actual event payload here as the full harness does.
  node -e '
    const fs = require("node:fs");
    const [source, target] = process.argv.slice(1);
    const { scenario: _scenario, ...event } = JSON.parse(fs.readFileSync(source, "utf-8"));
    fs.writeFileSync(target, JSON.stringify(event));
  ' "$file" "$event_file"

  echo -ne "  ${CYAN}[$((PASS+FAIL+1))/6]${NC} $name..."
  local exit_code=0
  cd "$PROJECT_DIR" && node --import tsx/esm "$CLI_ENTRY" check "$event_file" > /dev/null 2>&1 || exit_code=$?

  if [ "$exit_code" = "$expected_exit" ]; then
    echo -e " ${GREEN}✓ PASS${NC} (exit=$exit_code → $expected_label)"
    PASS=$((PASS+1))
  else
    echo -e " ${RED}✗ FAIL${NC} (exit=$exit_code, expected $expected_exit)"
    FAIL=$((FAIL+1))
  fi
}

check "Safe shell          " "$WORKSPACE_DIR/test-cases/scenarios/01-safe-read.json" 0 "allow"
check "curl | bash        " "$WORKSPACE_DIR/test-cases/scenarios/02-curl-bash.json" 3 "block"
check "API key email      " "$WORKSPACE_DIR/test-cases/scenarios/07-secret-email.json" 3 "block"
check "Bearer token HTTP  " "$WORKSPACE_DIR/test-cases/scenarios/08-secret-http.json" 3 "block"
check "Untrusted shell    " "$WORKSPACE_DIR/test-cases/scenarios/10-untrusted-web-shell.json" 2 "ask_approval"
check "Customer data email" "$WORKSPACE_DIR/test-cases/scenarios/12-customer-data-email.json" 2 "ask_approval"

echo ""
echo -e "${BOLD}──────────────────────────────────────────────────────────${NC}"
echo -e "  ${BOLD}PASS:${NC} $PASS  ${BOLD}FAIL:${NC} $FAIL  ${BOLD}TOTAL:${NC} $((PASS+FAIL))"
echo -e "${BOLD}──────────────────────────────────────────────────────────${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
  exit 1
fi
