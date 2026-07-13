#!/bin/bash
# ============================================================================
# RiskProof + LangGraph Agent — Demo Runner
# ============================================================================
# Syncs the locked Python environment, installs dependencies, and runs the
# interactive demo. Requires Node.js (for the RiskProof proxy and mock
# upstream server), uv, and Python 3.10+.
#
# Usage:
#   ./run.sh                    # Interactive scenario menu
#   ./run.sh --all              # Run all scenarios sequentially
#   ./run.sh --scenario 2       # Run a specific scenario
#   ./run.sh --help             # Show help
#
# Environment variables:
#   OPENAI_API_KEY   Required. OpenAI-compatible API key.
#   OPENAI_BASE_URL  Optional. OpenAI-compatible endpoint.
#   DEEPSEEK_API_KEY Optional. DeepSeek API key alias.
#   DEEPSEEK_BASE_URL Optional. DeepSeek endpoint alias.
#   LLM_MODEL        Optional. Model name (default: gpt-4o).
# ============================================================================

set -euo pipefail
cd "$(dirname "$0")"

# ── Colors ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  RiskProof + LangGraph Agent — Setup${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════════${NC}"
echo ""

# ── Check Node.js ───────────────────────────────────────────────────────────
if ! command -v node &> /dev/null; then
    echo -e "${RED}Error: Node.js is not installed.${NC}"
    echo "Install from https://nodejs.org/ or via nvm."
    exit 1
fi

NODE_VERSION=$(node --version)
NODE_MAJOR=$(node -p "Number(process.versions.node.split('.')[0])")
if [ "$NODE_MAJOR" -lt 22 ]; then
    echo -e "${RED}Error: Node.js 22+ is required; found ${NODE_VERSION}.${NC}"
    exit 1
fi
echo -e "  ${GREEN}[OK]${NC} Node.js ${NODE_VERSION}"

# ── Check npx ───────────────────────────────────────────────────────────────
if ! command -v npx &> /dev/null; then
    echo -e "${RED}Error: npx is not available.${NC}"
    exit 1
fi
echo -e "  ${GREEN}[OK]${NC} npx available"

# ── Install npm deps if needed ──────────────────────────────────────────────
if [ ! -d "../node_modules" ]; then
    echo -e "  ${YELLOW}[...]${NC} Installing npm dependencies..."
    (cd .. && npm ci) || {
        echo -e "  ${RED}[FAIL]${NC} npm ci failed"
        exit 1
    }
fi
echo -e "  ${GREEN}[OK]${NC} npm dependencies"

# ── Sync locked Python environment ─────────────────────────────────────────
if ! command -v uv &> /dev/null; then
    echo -e "${RED}Error: uv is required for the reproducible Python environment.${NC}"
    echo "Install it from https://docs.astral.sh/uv/getting-started/installation/"
    exit 1
fi
echo -e "  ${GREEN}[OK]${NC} $(uv --version)"

echo -e "  ${YELLOW}[...]${NC} Syncing frozen Python dependencies..."
uv sync --frozen --extra dev --quiet
uv pip check --quiet
PYTHON_VERSION=$(uv run python --version 2>&1)
echo -e "  ${GREEN}[OK]${NC} ${PYTHON_VERSION} with locked dependencies"

# ── Check API key ───────────────────────────────────────────────────────────
if [ -z "${OPENAI_API_KEY:-}" ] && [ -z "${DEEPSEEK_API_KEY:-}" ] && [ ! -f ".env" ]; then
        echo ""
        echo -e "  ${YELLOW}OPENAI_API_KEY / DEEPSEEK_API_KEY is not set.${NC}"
        echo -e "  You can set it with: export OPENAI_API_KEY=sk-..."
        echo -e "  Or create a .env file in the agent/ directory with:"
        echo -e "    OPENAI_API_KEY=sk-..."
        echo -e "    DEEPSEEK_API_KEY=sk-..."
        echo -e "    OPENAI_BASE_URL=https://api.openai.com/v1  # optional"
        echo -e "    DEEPSEEK_BASE_URL=https://api.deepseek.com  # optional"
        echo -e "    LLM_MODEL=gpt-4o                             # optional"
        echo ""
        read -r -s -p "  Enter your API key now (input hidden, or Ctrl-C to quit): " API_KEY
        echo ""
        if [ -n "$API_KEY" ]; then
            export OPENAI_API_KEY="$API_KEY"
        else
            echo -e "${RED}No API key provided. Exiting.${NC}"
            exit 1
        fi
fi
echo -e "  ${GREEN}[OK]${NC} API key set"

# ── Run ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${BOLD}Starting demo...${NC}"
echo ""

uv run python demo.py "$@"
