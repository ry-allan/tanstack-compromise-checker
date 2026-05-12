#!/usr/bin/env bash
# check-tanstack-compromise.sh
# Detects compromised TanStack packages (CVE-2026-45321 / GHSA-g7cv-rxg3-hmpx)
# and checks for persistence artifacts left by the malicious payload.
#
# Usage: curl -sL <raw-url> | bash
#    or: chmod +x check-tanstack-compromise.sh && ./check-tanstack-compromise.sh [project-dir]
#    or: ./check-tanstack-compromise.sh --install-alias   # append safe-chain pm() to shell profile

set -euo pipefail

# ── Install safe-chain alias ────────────────────────────────────────────────

if [[ "${1:-}" == "--install-alias" ]]; then
  SHELL_NAME="$(basename "$SHELL")"
  case "$SHELL_NAME" in
    zsh)  PROFILE="$HOME/.zshrc" ;;
    bash) PROFILE="$HOME/.bashrc" ;;
    *)    echo "error: unsupported shell '$SHELL_NAME' — add the pm() function manually" >&2; exit 1 ;;
  esac

  MARKER="# safe-chain pm wrapper"
  if grep -qF "$MARKER" "$PROFILE" 2>/dev/null; then
    echo "pm() alias already installed in $PROFILE"
    exit 0
  fi

  cat >> "$PROFILE" << 'ALIAS_EOF'

# safe-chain pm wrapper
pm() {
  local pm
  if [[ -f bun.lockb ]]; then
    pm=bun
  elif [[ -f pnpm-lock.yaml ]]; then
    pm=pnpm
  elif [[ -f yarn.lock ]]; then
    pm=yarn
  elif [[ -f package-lock.json ]]; then
    pm=npm
  else
    pm=pnpm
  fi

  if ! command -v safe-chain &>/dev/null; then
    echo "safe-chain not found — installing @aikidosec/safe-chain globally..."
    command npm install -g @aikidosec/safe-chain@latest
  fi
  if ! command -v safe-chain &>/dev/null; then
    echo "error: safe-chain installation failed — refusing to run without supply chain protection" >&2
    return 1
  fi
  command safe-chain "$pm" "$@"
}
ALIAS_EOF

  echo "Installed pm() alias in $PROFILE"
  echo "Run 'source $PROFILE' or open a new terminal to activate"
  exit 0
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m'

FOUND=0
DIR="${1:-.}"

info()  { echo -e "${BOLD}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[✗]${NC} $1"; FOUND=1; }

echo ""
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  TanStack Supply Chain Compromise Check (CVE-2026-45321)${NC}"
echo -e "${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "  Advisory: ${BOLD}GHSA-g7cv-rxg3-hmpx${NC}"
echo -e "  Reference: https://snyk.io/blog/tanstack-npm-packages-compromised/"
echo -e "  Deep dive: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
echo ""

# ── Compromised packages and versions ────────────────────────────────────────

BAD_PACKAGES=(
  "@tanstack/arktype-adapter:1.166.12 1.166.15"
  "@tanstack/eslint-plugin-router:1.161.9 1.161.12"
  "@tanstack/eslint-plugin-start:0.0.4 0.0.7"
  "@tanstack/history:1.161.9 1.161.12"
  "@tanstack/nitro-v2-vite-plugin:1.154.12 1.154.15"
  "@tanstack/react-router:1.169.5 1.169.8"
  "@tanstack/react-router-devtools:1.166.16 1.166.19"
  "@tanstack/react-router-ssr-query:1.166.15 1.166.18"
  "@tanstack/react-start:1.167.68 1.167.71"
  "@tanstack/react-start-client:1.166.51 1.166.54"
  "@tanstack/react-start-rsc:0.0.47 0.0.50"
  "@tanstack/react-start-server:1.166.55 1.166.58"
  "@tanstack/router-cli:1.166.46 1.166.49"
  "@tanstack/router-core:1.169.5 1.169.8"
  "@tanstack/router-devtools:1.166.16 1.166.19"
  "@tanstack/router-devtools-core:1.167.6 1.167.9"
  "@tanstack/router-generator:1.166.45 1.166.48"
  "@tanstack/router-plugin:1.167.38 1.167.41"
  "@tanstack/router-ssr-query-core:1.168.3 1.168.6"
  "@tanstack/router-utils:1.161.11 1.161.14"
  "@tanstack/router-vite-plugin:1.166.53 1.166.56"
  "@tanstack/solid-router:1.169.5 1.169.8"
  "@tanstack/solid-router-devtools:1.166.16 1.166.19"
  "@tanstack/solid-router-ssr-query:1.166.15 1.166.18"
  "@tanstack/solid-start:1.167.65 1.167.68"
  "@tanstack/solid-start-client:1.166.50 1.166.53"
  "@tanstack/solid-start-server:1.166.54 1.166.57"
  "@tanstack/start-client-core:1.168.5 1.168.8"
  "@tanstack/start-fn-stubs:1.161.9 1.161.12"
  "@tanstack/start-plugin-core:1.169.23 1.169.26"
  "@tanstack/start-server-core:1.167.33 1.167.36"
  "@tanstack/start-static-server-functions:1.166.44 1.166.47"
  "@tanstack/start-storage-context:1.166.38 1.166.41"
  "@tanstack/valibot-adapter:1.166.12 1.166.15"
  "@tanstack/virtual-file-routes:1.161.10 1.161.13"
  "@tanstack/vue-router:1.169.5 1.169.8"
  "@tanstack/vue-router-devtools:1.166.16 1.166.19"
  "@tanstack/vue-router-ssr-query:1.166.15 1.166.18"
  "@tanstack/vue-start:1.167.61 1.167.64"
  "@tanstack/vue-start-client:1.166.46 1.166.49"
  "@tanstack/vue-start-server:1.166.50 1.166.53"
  "@tanstack/zod-adapter:1.166.12 1.166.15"
)

# Worm-propagated secondary victims (non-TanStack)
SECONDARY_PACKAGES=(
  "@mistralai/mistralai:2.2.3 2.2.4"
  "@mistralai/mistralai-azure:1.7.2 1.7.3"
  "@mistralai/mistralai-gcp:1.7.2 1.7.3"
  "@opensearch-project/opensearch:3.6.2"
  "@draftlab/auth:0.24.1 0.24.2"
  "@draftlab/auth-router:0.5.1 0.5.2"
  "@draftlab/db:0.16.1 0.16.2"
  "@draftauth/client:0.2.1 0.2.2"
  "@draftauth/core:0.13.1 0.13.2"
  "@dirigible-ai/sdk:0.6.2 0.6.3"
  "safe-action:0.8.3 0.8.4"
  "cmux-agent-mcp:0.1.3 0.1.4 0.1.5 0.1.6 0.1.7 0.1.8"
  "nextmove-mcp:0.1.3 0.1.4 0.1.5 0.1.6 0.1.7"
  "git-git-git:1.0.8 1.0.9 1.0.10 1.0.11 1.0.12"
  "git-branch-selector:1.3.3 1.3.4 1.3.5 1.3.6 1.3.7"
  "agentwork-cli:0.1.4 0.1.5"
  "ml-toolkit-ts:1.0.4 1.0.5"
  "wot-api:0.8.1 0.8.2 0.8.3 0.8.4"
  "cross-stitch:1.1.3 1.1.4 1.1.5 1.1.6"
  "ts-dna:3.0.1 3.0.2 3.0.3 3.0.4"
)

# Known payload file SHA-256 hashes
HASH_ROUTER_INIT="ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
HASH_TANSTACK_RUNNER="2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"

# ── Step 1: Detect package manager ───────────────────────────────────────────

info "Scanning: $(cd "$DIR" && pwd)"
echo ""

PM=""
LOCKFILE=""
if [[ -f "$DIR/pnpm-lock.yaml" ]]; then
  PM="pnpm"
  LOCKFILE="pnpm-lock.yaml"
elif [[ -f "$DIR/yarn.lock" ]]; then
  PM="yarn"
  LOCKFILE="yarn.lock"
elif [[ -f "$DIR/bun.lockb" ]]; then
  PM="bun"
  LOCKFILE="bun.lockb"
elif [[ -f "$DIR/bun.lock" ]]; then
  PM="bun"
  LOCKFILE="bun.lock"
elif [[ -f "$DIR/package-lock.json" ]]; then
  PM="npm"
  LOCKFILE="package-lock.json"
fi

if [[ -z "$PM" ]]; then
  warn "No lockfile found in $DIR — checking node_modules directly"
else
  info "Package manager: ${BOLD}$PM${NC} ($LOCKFILE)"
fi
echo ""

# ── Step 2: Check for compromised TanStack packages ─────────────────────────

info "Checking installed TanStack packages against 42 known-compromised versions (CVE-2026-45321)..."

check_package() {
  local pkg="$1"
  local bad_vers="$2"
  local pjson="$DIR/node_modules/$pkg/package.json"

  [[ -f "$pjson" ]] || return 0

  local ver
  ver=$(grep -o '"version": *"[^"]*"' "$pjson" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || true)
  [[ -n "$ver" ]] || return 0

  for bad in $bad_vers; do
    if [[ "$ver" == "$bad" ]]; then
      fail "${RED}COMPROMISED${NC}: $pkg@$ver"
      return
    fi
  done
  ok "$pkg@$ver — clean"
}

for entry in "${BAD_PACKAGES[@]}"; do
  pkg="${entry%%:*}"
  vers="${entry#*:}"
  check_package "$pkg" "$vers"
done

echo ""

info "Checking worm-propagated secondary victims (Mini Shai-Hulud self-replication targets)..."
info "  Packages: @mistralai, @opensearch-project, @draftlab, @draftauth,"
info "  @dirigible-ai, safe-action, cmux-agent-mcp, nextmove-mcp,"
info "  git-git-git, git-branch-selector, agentwork-cli, ml-toolkit-ts,"
info "  wot-api, cross-stitch, ts-dna"

for entry in "${SECONDARY_PACKAGES[@]}"; do
  pkg="${entry%%:*}"
  vers="${entry#*:}"
  check_package "$pkg" "$vers"
done

echo ""

# ── Step 3: Check lockfile for compromised versions ──────────────────────────

info "Scanning lockfile for known-compromised versions (${LOCKFILE:-none detected})..."

lockfile_contains_package_version() {
  local pkg="$1"
  local ver="$2"
  local lockfile_path="$DIR/$LOCKFILE"

  case "$LOCKFILE" in
    package-lock.json)
      awk -v pkg="$pkg" -v ver="$ver" '
        function starts_package(line) {
          return index(line, "\"" pkg "\": {") || index(line, "\"node_modules/" pkg "\": {")
        }
        starts_package($0) {
          in_pkg = 1
          depth = 1
          if (index($0, "\"version\"") && index($0, "\"" ver "\"")) {
            found = 1
          }
          next
        }
        in_pkg {
          if (index($0, "\"version\"") && index($0, "\"" ver "\"")) {
            found = 1
          }
          opens = gsub(/\{/, "{")
          closes = gsub(/\}/, "}")
          depth += opens - closes
          if (depth <= 0) {
            in_pkg = 0
          }
        }
        END { exit(found ? 0 : 1) }
      ' "$lockfile_path"
      ;;
    yarn.lock)
      awk -v pkg="$pkg" -v ver="$ver" '
        /^[^[:space:]][^:]*:$/ {
          in_pkg = index($0, pkg) > 0
          next
        }
        in_pkg && $1 == "version" && $2 == "\"" ver "\"" {
          found = 1
        }
        END { exit(found ? 0 : 1) }
      ' "$lockfile_path"
      ;;
    *)
      grep -qE "${pkg}.*${ver}" "$lockfile_path" 2>/dev/null
      ;;
  esac
}

if [[ -n "$LOCKFILE" && -f "$DIR/$LOCKFILE" ]]; then
  LOCKFILE_FOUND=false
  for entry in "${BAD_PACKAGES[@]}" "${SECONDARY_PACKAGES[@]}"; do
    pkg="${entry%%:*}"
    vers="${entry#*:}"
    for ver in $vers; do
      if lockfile_contains_package_version "$pkg" "$ver"; then
        fail "Lockfile contains $pkg@$ver"
        LOCKFILE_FOUND=true
      fi
    done
  done
  if [[ "$LOCKFILE_FOUND" == false ]]; then
    ok "No compromised versions in lockfile"
  fi
else
  warn "No lockfile to scan"
fi

echo ""

# ── Step 4: Check for payload artifacts ──────────────────────────────────────

info "Checking for persistence artifacts (payload files, hooks, services, C2 indicators)..."

ARTIFACTS=(
  "$HOME/.claude/router_runtime.js"
  "$HOME/.claude/setup.mjs"
  "$HOME/.vscode/setup.mjs"
  "$HOME/.local/bin/gh-token-monitor.sh"
  "$HOME/.config/gh-token-monitor/token"
  "$HOME/Library/LaunchAgents/com.user.gh-token-monitor.plist"
  ".claude/router_runtime.js"
  ".claude/setup.mjs"
  ".vscode/setup.mjs"
)

for artifact in "${ARTIFACTS[@]}"; do
  target="$DIR/$artifact"
  [[ "$artifact" == "$HOME"* ]] && target="$artifact"
  if [[ -f "$target" ]]; then
    fail "Payload artifact found: $target"
  fi
done

# Check for Claude Code SessionStart hook injection
for CLAUDE_SETTINGS in "$DIR/.claude/settings.json" "$HOME/.claude/settings.json"; do
  if [[ -f "$CLAUDE_SETTINGS" ]]; then
    if grep -qE "router_runtime|setup\.mjs|tanstack_runner" "$CLAUDE_SETTINGS" 2>/dev/null; then
      fail "Malicious SessionStart hook in $CLAUDE_SETTINGS"
    fi
  fi
done

# Check for VS Code tasks.json folderOpen persistence
VSCODE_TASKS="$DIR/.vscode/tasks.json"
if [[ -f "$VSCODE_TASKS" ]]; then
  if grep -qE "router_runtime|setup\.mjs|tanstack_runner" "$VSCODE_TASKS" 2>/dev/null; then
    fail "Malicious folderOpen task in $VSCODE_TASKS"
  fi
fi

# Check for injected GitHub workflows
WORKFLOW="$DIR/.github/workflows/codeql_analysis.yml"
if [[ -f "$WORKFLOW" ]]; then
  if grep -q "claude@users.noreply.github.com" "$WORKFLOW" 2>/dev/null; then
    fail "Malicious workflow detected: $WORKFLOW"
  fi
fi

# Check all workflows for toJSON(secrets) exfiltration pattern
if [[ -d "$DIR/.github/workflows" ]]; then
  while IFS= read -r wf; do
    if grep -q 'toJSON(secrets)' "$wf" 2>/dev/null; then
      fail "Workflow exfiltrates secrets via toJSON(secrets): $wf"
    fi
  done < <(find "$DIR/.github/workflows" -name "*.yml" -o -name "*.yaml" 2>/dev/null)
fi

# Cache git state for reuse (branch check + history audit)
IS_GIT_REPO=false
GIT_BRANCHES=""
if command -v git &>/dev/null && git -C "$DIR" rev-parse --is-inside-work-tree &>/dev/null 2>&1; then
  IS_GIT_REPO=true
  GIT_BRANCHES=$(git -C "$DIR" branch -a 2>/dev/null || true)
fi

# Check for worm's dependabot/dependabout branch patterns (both variants seen in the wild)
if [[ "$IS_GIT_REPO" == true && -n "$GIT_BRANCHES" ]]; then
  if echo "$GIT_BRANCHES" | grep -qE "dependabot/github_actions/format/"; then
    fail "Suspicious worm branch pattern: dependabot/github_actions/format/*"
  fi
  if echo "$GIT_BRANCHES" | grep -qE "dependabout/.*/setup-formatter"; then
    fail "Suspicious worm branch pattern: dependabout/*/setup-formatter"
  fi
fi

# Check for gh-token-monitor service (macOS)
if launchctl list 2>/dev/null | grep -q "gh-token-monitor"; then
  fail "Malicious LaunchAgent 'gh-token-monitor' is running"
elif ls "$HOME/Library/LaunchAgents/"*gh-token-monitor* &>/dev/null; then
  fail "Malicious LaunchAgent 'gh-token-monitor' found on disk"
fi

# Check for gh-token-monitor service (Linux systemd)
if [[ -f "$HOME/.config/systemd/user/gh-token-monitor.service" ]]; then
  fail "Malicious systemd user service: gh-token-monitor.service"
fi
if systemctl --user is-active gh-token-monitor &>/dev/null 2>&1; then
  fail "Malicious systemd service 'gh-token-monitor' is running"
fi

# Resolve hash command once
if command -v sha256sum &>/dev/null; then
  hash_file() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
else
  hash_file() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
fi

# Check for known TanStack payload files in node_modules (single find, SHA-256 verification)
if [[ -d "$DIR/node_modules" ]]; then
  while IFS= read -r payload_path; do
    payload_name="${payload_path##*/}"
    if [[ "$payload_name" == "router_init.js" ]]; then
      expected_hash="$HASH_ROUTER_INIT"
    else
      expected_hash="$HASH_TANSTACK_RUNNER"
    fi
    actual_hash=$(hash_file "$payload_path")
    if [[ "$actual_hash" == "$expected_hash" ]]; then
      fail "CONFIRMED malicious $payload_name (SHA-256 match): $payload_path"
    else
      fail "Suspicious $payload_name found (hash mismatch — verify manually): $payload_path"
    fi
  done < <(find "$DIR/node_modules" \( -name "router_init.js" -o -name "tanstack_runner.js" \) 2>/dev/null)
fi

# Check for @tanstack/setup optionalDependency (primary infection vector)
if [[ -d "$DIR/node_modules" ]]; then
  SETUP_HITS=$(find "$DIR/node_modules" -name "package.json" -exec grep -l '"@tanstack/setup"' {} + 2>/dev/null || true)
  if [[ -n "$SETUP_HITS" ]]; then
    while IFS= read -r hit; do
      fail "Malicious @tanstack/setup optionalDependency in: $hit"
    done <<< "$SETUP_HITS"
  fi
fi

# Check for daemonized payload processes
if pgrep -f "router_init\.js|tanstack_runner\.js|router_runtime\.js|setup\.mjs.*tanstack" &>/dev/null; then
  fail "Active payload process detected (router_init/tanstack_runner/router_runtime)"
fi
if pgrep -f "gh-token-monitor" &>/dev/null; then
  fail "Active gh-token-monitor process detected"
fi

# Check for malicious git commits in repo history (reuses cached IS_GIT_REPO)
if [[ "$IS_GIT_REPO" == true ]]; then
  if git -C "$DIR" log --all --author="claude@users.noreply.github.com" --oneline 2>/dev/null | grep -q .; then
    fail "Git history contains commits by claude@users.noreply.github.com"
  else
    ok "No malicious author commits in git history"
  fi
fi

# Check npm token list for ransom-marked tokens
if command -v npm &>/dev/null; then
  if npm token list 2>/dev/null | grep -qi "IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner"; then
    fail "npm token with destructive-revocation marker found — DO NOT revoke until persistence is removed"
  fi
fi

# Check AI tool config files for tampering
for ai_config in "$HOME/.claude/mcp.json" "$HOME/.kiro/settings/mcp.json"; do
  if [[ -f "$ai_config" ]]; then
    if grep -qE "router_runtime|tanstack_runner|setup\.mjs|masscan\.cloud|getsession\.org|git-tanstack\.com" "$ai_config" 2>/dev/null; then
      fail "Malicious entry in AI tool config: $ai_config"
    fi
  fi
done

# Check for payload IOCs and C2 domains in codebase (single find pass, combined regex)
TANSTACK_IOCS="github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c|zblgg/configuration|filev2\.getsession\.org|seed[123]\.getsession\.org|litter\.catbox\.moe/(h8nc9u\.js|7rrc6l\.mjs)|svksjrhjkcejg|EveryBoiWeBuildIsAWormyBoi"
C2_DOMAINS="api\.masscan\.cloud|git-tanstack\.com"
IOC_FOUND=false
C2_FOUND=false
while IFS= read -r source_file; do
  if [[ "$IOC_FOUND" == false ]] && grep -qE "$TANSTACK_IOCS" "$source_file" 2>/dev/null; then
    fail "TanStack payload IOC found in source files"
    IOC_FOUND=true
  fi
  if [[ "$C2_FOUND" == false ]] && grep -qE "$C2_DOMAINS" "$source_file" 2>/dev/null; then
    fail "C2 domain reference found in source files (api.masscan.cloud or git-tanstack.com)"
    C2_FOUND=true
  fi
  [[ "$IOC_FOUND" == true && "$C2_FOUND" == true ]] && break
done < <(find "$DIR" -path "$DIR/node_modules" -prune -o \( -name "*.js" -o -name "*.mjs" -o -name "*.ts" -o -name "*.json" \) -type f -print 2>/dev/null)

echo ""

# ── Summary ──────────────────────────────────────────────────────────────────

echo -e "${BOLD}───────────────────────────────────────────────────────────────${NC}"
if [[ $FOUND -eq 0 ]]; then
  ok "${GREEN}${BOLD}No compromise detected.${NC}"
else
  fail "${RED}${BOLD}COMPROMISED — take action immediately:${NC}"
  echo ""
  echo -e "  ${RED}WARNING: gh-token-monitor runs 'rm -rf ~/' if tokens are revoked.${NC}"
  echo -e "  ${RED}Kill persistence BEFORE rotating any secrets.${NC}"
  echo ""
  echo "  1. Disconnect CI runners from network"
  echo "  2. Kill persistence (launchctl unload, systemctl --user stop gh-token-monitor, remove hooks)"
  echo "  3. Remove all artifacts listed above"
  echo "  4. Remove and reinstall node_modules from clean lockfile"
  echo "  5. THEN rotate ALL secrets (GitHub tokens, npm tokens, AWS keys, Vault tokens, SSH keys)"
  echo "  6. Audit git history for commits by claude@users.noreply.github.com"
  echo "  7. Check for branches matching dependabot/github_actions/format/* or dependabout/*/setup-formatter"
  echo "  8. Check npm token list — DO NOT revoke tokens described 'IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner' until machine is imaged"
  echo "  9. Check ~/.aws, ~/.ssh, ~/.npmrc, ~/.docker/config.json for exfiltration"
  echo " 10. Block at DNS: *.getsession.org, api.masscan.cloud, git-tanstack.com, litter.catbox.moe"
  echo " 11. See: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem"
fi
echo ""

# ── Suggest safe-chain alias ────────────────────────────────────────────────

echo -e "${BOLD}───────────────────────────────────────────────────────────────${NC}"
echo -e "  ${BOLD}Prevent future supply-chain attacks${NC}"
echo ""
echo "  Run with --install-alias to add a pm() shell function that wraps"
echo "  every npm/pnpm/yarn/bun install through Aikido's safe-chain scanner."
echo "  safe-chain blocks packages younger than 48 hours and flags known-bad"
echo "  versions before they touch node_modules."
echo ""
echo -e "    ${BOLD}$0 --install-alias${NC}"
echo ""

exit $FOUND
