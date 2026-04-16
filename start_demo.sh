#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Prisma AIRS × AgentCore — Demo Launcher
# ─────────────────────────────────────────────────────────────────────────────
# Usage:
#   ./start_demo.sh          # Start agent server (foreground, with live logs)
#   ./start_demo.sh --check  # Run dependency & connectivity checks only
#   ./start_demo.sh --bg     # Start agent server in background
#
# In a second terminal, run the attack dashboard:
#   python3 run_attacks.py
#
# Prerequisites (see .env.example):
#   export PRISMA_AIRS_API_KEY="<your-key>"
#   export PRISMA_AIRS_PROFILE_NAME="<your-profile>"
#   export AWS_ACCESS_KEY_ID="<key>"
#   export AWS_SECRET_ACCESS_KEY="<secret>"
#   export AWS_DEFAULT_REGION="us-west-2"
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"
LOG_FILE="/tmp/prisma-airs-demo.log"
SERVER_PID_FILE="/tmp/airs_demo_server.pid"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✔${RESET}  $*"; }
fail() { echo -e "  ${RED}✖${RESET}  $*"; }
info() { echo -e "  ${CYAN}ℹ${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
hdr()  { echo -e "\n${BOLD}$*${RESET}"; }

# ── Banner ────────────────────────────────────────────────────────────────────
print_banner() {
  echo -e "${BOLD}${CYAN}"
  echo "  ╔═══════════════════════════════════════════════════════════╗"
  echo "  ║   PRISMA AIRS  ×  AWS BEDROCK AGENTCORE  — DEMO LAUNCHER ║"
  echo "  ╚═══════════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

# ── Load environment ──────────────────────────────────────────────────────────
load_env() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a; source "$ENV_FILE"; set +a
    ok "Loaded credentials from $ENV_FILE"
  else
    warn ".env not found at $ENV_FILE — relying on shell environment"
    info "Copy .env.example to .env and fill in your credentials."
  fi
}

# ── Dependency checks ─────────────────────────────────────────────────────────
check_deps() {
  hdr "1/4  Checking system dependencies"
  local all_ok=true

  command -v python3 &>/dev/null \
    && ok "python3 $(python3 --version 2>&1 | cut -d' ' -f2)" \
    || { fail "python3 not found"; all_ok=false; }

  command -v jq &>/dev/null \
    && ok "jq $(jq --version)" \
    || { fail "jq not found — run: sudo apt install -y jq"; all_ok=false; }

  command -v curl &>/dev/null \
    && ok "curl $(curl --version | head -1 | cut -d' ' -f2)" \
    || { fail "curl not found"; all_ok=false; }

  command -v aws &>/dev/null \
    && ok "aws-cli $(aws --version 2>&1 | cut -d' ' -f1)" \
    || warn "aws CLI not found — Bedrock model calls will fail"

  for pkg in fastapi uvicorn rich strands requests; do
    python3 -c "import ${pkg//-/_}" &>/dev/null \
      && ok "python: $pkg" \
      || { fail "python: $pkg missing — run: pip install $pkg"; all_ok=false; }
  done

  python3 -c "import bedrock_agentcore" &>/dev/null \
    && ok "python: bedrock-agentcore" \
    || warn "bedrock-agentcore not installed (optional for local demo)"

  $all_ok || { echo; fail "Fix the above issues, then re-run."; exit 1; }
}

# ── Credential checks ─────────────────────────────────────────────────────────
check_credentials() {
  hdr "2/4  Checking credentials"

  [[ -n "${PRISMA_AIRS_API_KEY:-}" ]] \
    && ok "PRISMA_AIRS_API_KEY set (${PRISMA_AIRS_API_KEY:0:12}...)" \
    || { fail "PRISMA_AIRS_API_KEY not set — see .env.example"; exit 1; }

  [[ -n "${PRISMA_AIRS_PROFILE_NAME:-}" ]] \
    && ok "PRISMA_AIRS_PROFILE_NAME: $PRISMA_AIRS_PROFILE_NAME" \
    || { fail "PRISMA_AIRS_PROFILE_NAME not set — see .env.example"; exit 1; }

  [[ -n "${AWS_ACCESS_KEY_ID:-}" ]] \
    && ok "AWS_ACCESS_KEY_ID set" \
    || warn "AWS_ACCESS_KEY_ID not set — Bedrock calls will fail"

  [[ -n "${AWS_SESSION_TOKEN:-}" ]] \
    && ok "AWS_SESSION_TOKEN set (STS session active)" \
    || warn "AWS_SESSION_TOKEN not set — using long-term credentials"
}

# ── AIRS connectivity ─────────────────────────────────────────────────────────
check_airs() {
  hdr "3/4  Testing Prisma AIRS API connectivity"

  local url="${PRISMA_AIRS_URL:-https://service.api.aisecurity.paloaltonetworks.com}"
  local payload
  payload=$(jq -n \
    --arg profile "${PRISMA_AIRS_PROFILE_NAME}" \
    '{tr_id:"demo-check-001",ai_profile:{profile_name:$profile},
      metadata:{app_name:"start_demo_check"},contents:[{prompt:"connectivity test"}]}')

  local resp
  resp=$(curl -s --max-time 10 \
    -H "Content-Type: application/json" \
    -H "x-pan-token: ${PRISMA_AIRS_API_KEY}" \
    "${url}/v1/scan/sync/request" \
    -d "$payload" 2>&1)

  local action
  action=$(echo "$resp" | jq -r '.action // "error"' 2>/dev/null)

  if [[ "$action" == "allow" || "$action" == "block" ]]; then
    ok "AIRS API reachable — action: $action"
  else
    fail "AIRS API not reachable or returned unexpected response:"
    echo "       ${resp:0:200}"
    exit 1
  fi
}

# ── AWS Bedrock check ─────────────────────────────────────────────────────────
check_bedrock() {
  hdr "4/4  Testing AWS identity"

  if ! command -v aws &>/dev/null; then
    warn "aws CLI not found — skipping AWS check"
    return
  fi

  local identity
  identity=$(aws sts get-caller-identity --output json 2>&1)
  if echo "$identity" | jq -e '.Account' &>/dev/null; then
    local acct arn
    acct=$(echo "$identity" | jq -r '.Account')
    arn=$(echo "$identity" | jq -r '.Arn')
    ok "AWS identity verified: $arn"
    info "Account: $acct"
  else
    warn "AWS STS call failed — Bedrock calls may fail"
    warn "$(echo "$identity" | head -1)"
  fi
}

# ── Port cleanup ───────────────────────────────────────────────────────────────
kill_existing_server() {
  if [[ -f "$SERVER_PID_FILE" ]]; then
    local old_pid
    old_pid=$(cat "$SERVER_PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null; then
      info "Stopping existing demo server (PID $old_pid)"
      kill "$old_pid" 2>/dev/null || true
      sleep 1
    fi
    rm -f "$SERVER_PID_FILE"
  fi

  local pids
  pids=$(lsof -ti tcp:8080 2>/dev/null || true)
  if [[ -n "$pids" ]]; then
    info "Freeing port 8080 (PID $pids)"
    echo "$pids" | xargs kill 2>/dev/null || true
    sleep 1
  fi
}

# ── Usage instructions ────────────────────────────────────────────────────────
print_instructions() {
  echo
  echo -e "${BOLD}${GREEN}  ═══════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}  HOW TO RUN THE DEMO${RESET}"
  echo -e "${BOLD}${GREEN}  ═══════════════════════════════════════════════════════════${RESET}"
  echo
  echo -e "  ${BOLD}Terminal 1 (this window):${RESET}"
  echo -e "    ${CYAN}./start_demo.sh${RESET}"
  echo -e "    → Agent server on http://localhost:8080"
  echo -e "    → Watch real-time AIRS intercept messages here"
  echo
  echo -e "  ${BOLD}Terminal 2 (new tab):${RESET}"
  echo -e "    ${CYAN}source .env && python3 run_attacks.py${RESET}"
  echo -e "    → Interactive attack dashboard (13 tests)"
  echo -e "    → Select attack numbers 1-13 to see AIRS blocking"
  echo
  echo -e "  ${BOLD}Automated full run:${RESET}"
  echo -e "    ${CYAN}python3 run_attacks.py --auto${RESET}"
  echo -e "    → Runs all 13 tests and prints a summary table"
  echo
  echo -e "${BOLD}${GREEN}  ═══════════════════════════════════════════════════════════${RESET}"
  echo
}

# ── Start server ──────────────────────────────────────────────────────────────
start_server_foreground() {
  echo -e "\n${BOLD}${CYAN}  Starting Prisma AIRS Demo Agent Server...${RESET}"
  echo -e "  ${CYAN}→ POST http://localhost:8080/invocations${RESET}"
  echo -e "  ${CYAN}→ GET  http://localhost:8080/health${RESET}"
  echo -e "  ${YELLOW}  (Ctrl+C to stop)${RESET}\n"
  exec python3 "$SCRIPT_DIR/demo_agent_server.py"
}

start_server_background() {
  echo -e "\n  Starting agent server in background..."
  nohup python3 "$SCRIPT_DIR/demo_agent_server.py" \
    > /tmp/airs_demo_server.log 2>&1 &
  local pid=$!
  echo "$pid" > "$SERVER_PID_FILE"
  ok "Agent server started (PID $pid) — logs: /tmp/airs_demo_server.log"

  local retries=0
  while ! curl -s http://localhost:8080/health &>/dev/null; do
    sleep 1
    retries=$((retries + 1))
    if [[ $retries -gt 20 ]]; then
      fail "Server did not start within 20s — check /tmp/airs_demo_server.log"
      exit 1
    fi
  done
  ok "Server is ready at http://localhost:8080"
}

# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

print_banner
load_env
check_deps
check_credentials
check_airs
check_bedrock

MODE="${1:-}"

if [[ "$MODE" == "--check" ]]; then
  echo
  ok "All checks passed. You're ready to demo."
  print_instructions
  exit 0
fi

kill_existing_server
print_instructions

if [[ "$MODE" == "--bg" ]]; then
  start_server_background
  echo
  info "Now run the attack dashboard in this terminal:"
  echo -e "  ${CYAN}python3 run_attacks.py${RESET}"
  echo
else
  start_server_foreground
fi
