#!/usr/bin/env bash
# ============================================================================
# RiskProof Test Workspace — 全场景测试脚本
# ============================================================================
# 用法:
#   bash test-workspace/scripts/run-all-tests.sh                    # 全部测试
#   bash test-workspace/scripts/run-all-tests.sh --scenario S02     # 单个场景
#   bash test-workspace/scripts/run-all-tests.sh --category block   # 按类别
#   bash test-workspace/scripts/run-all-tests.sh --category approval
#   bash test-workspace/scripts/run-all-tests.sh --category allow
#
# 这个脚本完全绕过 Claude，直接调用 riskproof check，
# 因此不受 Claude 自身权限系统的限制。
# ============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKSPACE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_DIR="$(cd "$WORKSPACE_DIR/.." && pwd)"
SCENARIOS_DIR="$WORKSPACE_DIR/test-cases/scenarios"
CLI_ENTRY="$PROJECT_DIR/packages/riskproof/src/cli.ts"
PASS=0
FAIL=0
TOTAL=0

# ─── 颜色 ────────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
BOLD=$'\033[1m'
NC=$'\033[0m' # No Color

# ─── 期望结果映射 ────────────────────────────────────────────────────────────
# 每个场景文件的 scenario 字段包含 "→ ALLOW", "→ BLOCK", 或 "→ ASK_APPROVAL"
# 脚本自动从中提取期望的 exit code

# ─── 运行单个测试 ───────────────────────────────────────────────────────────

run_one_test() {
  local file="$1"
  local filename=$(basename "$file")

  # 从 scenario 字段提取期望结果
  local scenario_line=$(node -e "try{console.log(JSON.parse(require('fs').readFileSync('$file','utf8')).scenario)}catch(e){console.log('')}")
  local expected=""
  if echo "$scenario_line" | grep -q "ALLOW"; then
    expected="allow"
  elif echo "$scenario_line" | grep -q "BLOCK"; then
    expected="block"
  elif echo "$scenario_line" | grep -q "ASK_APPROVAL"; then
    expected="ask_approval"
  else
    expected="unknown"
  fi

  TOTAL=$((TOTAL + 1))

  # 运行 riskproof check
  local exit_code=0
  local output=""
  output=$(cd "$PROJECT_DIR" && node --import tsx/esm "$CLI_ENTRY" check "$file" 2>&1) || exit_code=$?

  # 解析输出
  local action=""
  local decision=""
  local risk=""
  local rules=""
  if echo "$output" | grep -q '"action"'; then
    action=$(echo "$output" | node -e "try{const j=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(j.action||'')}catch(e){}" 2>/dev/null || echo "parse_error")
    decision=$(echo "$output" | node -e "try{const j=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(j.decision||'')}catch(e){}" 2>/dev/null || echo "")
    risk=$(echo "$output" | node -e "try{const j=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log(j.riskLevel||'')}catch(e){}" 2>/dev/null || echo "")
    rules=$(echo "$output" | node -e "try{const j=JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));console.log((j.matchedRules||[]).map(r=>r.id).join(', ')||'none')}catch(e){}" 2>/dev/null || echo "")
  fi

  # 判断结果是否匹配
  local result_ok=false
  case "$expected" in
    allow) [ "$exit_code" = "0" ] && result_ok=true ;;
    block) [ "$exit_code" = "3" ] && result_ok=true ;;
    ask_approval) [ "$exit_code" = "2" ] && result_ok=true ;;
  esac

  local icon=""
  local status=""
  if $result_ok; then
    icon="${GREEN}✓${NC}"
    status="${GREEN}PASS${NC}"
    PASS=$((PASS + 1))
  else
    icon="${RED}✗${NC}"
    status="${RED}FAIL${NC}"
    FAIL=$((FAIL + 1))
  fi

  # 输出结果行
  printf "  %s %-6s %-55s" "$icon" "$status" "$filename"
  printf " expected=%-13s actual=%-13s exit=%-2s" "$expected" "$action" "$exit_code"
  if [ -n "$rules" ] && [ "$rules" != "none" ]; then
    printf "  rules: %s" "$rules"
  fi
  printf "\n"

  # 失败时输出详细信息
  if ! $result_ok; then
    echo -e "    ${YELLOW}Detail:${NC} $output" | head -5
    echo ""
  fi
}

# ─── 主函数 ──────────────────────────────────────────────────────────────────

main() {
  echo ""
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
  echo -e "${BOLD}${CYAN}  RiskProof Test Harness — 全场景安全策略测试${NC}"
  echo -e "${BOLD}${CYAN}══════════════════════════════════════════════════════════════════════${NC}"
  echo ""
  echo -e "  ${BLUE}Mode:${NC} Direct CLI (完全绕过 Claude 权限系统)"
  echo -e "  ${BLUE}Engine:${NC} $CLI_ENTRY"
  echo ""

  # 收集测试文件
  local files=()
  for f in "$SCENARIOS_DIR"/*.json; do
    files+=("$f")
  done

  # 支持过滤
  local filter="$1"
  local filter_val="$2"
  if [ "$filter" = "--scenario" ] && [ -n "$filter_val" ]; then
    local old_files=("${files[@]}")
    files=()
    for f in "${old_files[@]}"; do
      local s=$(node -e "try{console.log(JSON.parse(require('fs').readFileSync('$f','utf8')).scenario)}catch(e){}")
      if [[ "$(basename "$f")" == *"$filter_val"* ]] || [[ "$s" == *"$filter_val"* ]]; then
        files+=("$f")
      fi
    done
    echo -e "  ${YELLOW}Filter:${NC} scenario matching '$filter_val'"
    echo ""
  elif [ "$filter" = "--category" ] && [ -n "$filter_val" ]; then
    local old_files=("${files[@]}")
    files=()
    for f in "${old_files[@]}"; do
      local s=$(node -e "try{console.log(JSON.parse(require('fs').readFileSync('$f','utf8')).scenario)}catch(e){}")
      case "$filter_val" in
        block) echo "$s" | grep -q "BLOCK" && files+=("$f") ;;
        approval) echo "$s" | grep -q "ASK_APPROVAL" && files+=("$f") ;;
        allow) echo "$s" | grep -q "ALLOW" && files+=("$f") ;;
      esac
    done
    echo -e "  ${YELLOW}Filter:${NC} expected = '$filter_val'"
    echo ""
  fi

  if [ ${#files[@]} -eq 0 ]; then
    echo -e "  ${RED}No test scenarios found matching filter${NC}"
    exit 1
  fi

  # 排序
  IFS=$'\n' files=($(sort <<<"${files[*]}"))
  unset IFS

  echo -e "  ${BOLD}Running ${#files[@]} test scenarios...${NC}"
  echo ""

  for f in "${files[@]}"; do
    run_one_test "$f"
  done

  # 汇总
  echo ""
  echo -e "${BOLD}──────────────────────────────────────────────────────────────────────${NC}"
  echo -e "  ${BOLD}Results:${NC}"
  echo -e "    ${GREEN}PASS:${NC}  $PASS"
  echo -e "    ${RED}FAIL:${NC}  $FAIL"
  echo -e "    TOTAL: $TOTAL"
  if [ $TOTAL -gt 0 ]; then
    local pass_rate=$((PASS * 100 / TOTAL))
    echo -e "    ${BOLD}Pass Rate:${NC} ${pass_rate}%"
  fi
  echo -e "${BOLD}──────────────────────────────────────────────────────────────────────${NC}"
  echo ""

  if [ $FAIL -gt 0 ]; then
    exit 1
  fi
}

main "$@"
