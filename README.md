# tanstack-compromise-checker

> **⚠️ Disclaimer:** This tool was built for my own use case. All indicators are derived from the following advisory sources:
> - [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
> - [Snyk: TanStack npm packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
> - [StepSecurity: Mini Shai-Hulud deep dive](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)
>
> If new IOCs, payload variants, or attacker infrastructure emerge after this was last updated, they won't be detected. Always cross-check against the latest published advisories.

Detects the TanStack supply chain compromise ([CVE-2026-45321](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)) and related Mini Shai-Hulud worm artifacts in a local project checkout.

The script is intended for fast triage in source checkouts, CI jobs, and Docker builds. A clean result means none of the known indicators below were found. It is not a full forensic investigation or a guarantee that a machine was never exposed.

## What it checks

| Category | Details |
|---|---|
| **Compromised packages** | All 42 `@tanstack/*` packages + 20 worm-propagated secondary victims (`@mistralai`, `@opensearch-project`, `@draftlab`, `safe-action`, etc.) |
| **Lockfile scan** | `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `bun.lockb`, `package-lock.json`, including multiline npm v3 `packages` entries and Yarn v1 selector/version stanzas |
| **Payload files** | `router_init.js`, `tanstack_runner.js` in `node_modules` with SHA-256 verification; exact hash matches and hash mismatches both fail the scan |
| **Infection vector** | `@tanstack/setup` as `optionalDependency` in any installed package |
| **Persistence** | Claude Code `SessionStart` hooks in both project and home settings, VS Code `folderOpen` tasks, `gh-token-monitor` (LaunchAgent + systemd), malicious GitHub workflows |
| **Disk artifacts** | `.claude/router_runtime.js`, `.claude/setup.mjs`, `.vscode/setup.mjs`, `gh-token-monitor.sh`, `com.user.gh-token-monitor.plist` |
| **Source IOCs** | Attacker commit hashes, C2 domains (`api.masscan.cloud`, `git-tanstack.com`), Session Protocol endpoints, PBKDF2 salt, campaign strings |
| **Git history** | Commits authored by `claude@users.noreply.github.com` |
| **Branch patterns** | `dependabot/github_actions/format/*` and `dependabout/*/setup-formatter` |
| **AI tool configs** | Tampered `.claude/mcp.json` and `.kiro/settings/mcp.json` |
| **Running processes** | Daemonized payload and `gh-token-monitor` processes |
| **npm tokens** | Ransom-marked tokens (`IfYouRevokeThisTokenItWillWipeTheComputerOfTheOwner`) |

## What it does not cover

- It checks known package names, versions, filenames, hashes, domains, branch names, and persistence paths from the public advisories. New attacker infrastructure or renamed payloads may require new indicators.
- It selects one project lockfile in package-manager priority order (`pnpm`, `yarn`, `bun`, then `npm`). If a repository intentionally carries multiple lockfiles, scan each relevant package-manager state separately.
- It can identify suspicious files and configuration, but it does not remove malware, rotate secrets, revoke tokens, or image the host.
- The npm token check only runs when `npm` is available and authenticated enough for `npm token list`.
- Home-directory persistence checks inspect the current `HOME` of the process running the script. In CI or containers, that may differ from a developer workstation home directory.

## Quick start

```bash
# Scan current directory
bash check-tanstack-compromise.sh .

# Scan a specific project
bash check-tanstack-compromise.sh /path/to/project

# One-liner (curl)
curl -sL https://raw.githubusercontent.com/ry-allan/tanstack-compromise-checker/main/check-tanstack-compromise.sh | bash
```

Exit code `0` = no covered indicators found.
Exit code `1` = covered compromise or suspicious payload indicator found.

### Sample output (clean project)

```
═══════════════════════════════════════════════════════════════
  TanStack Supply Chain Compromise Check (CVE-2026-45321)
═══════════════════════════════════════════════════════════════
  Advisory: GHSA-g7cv-rxg3-hmpx
  Reference: https://snyk.io/blog/tanstack-npm-packages-compromised/
  Deep dive: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-…

[*] Scanning: /Users/xxxxx/repos/xxxxx

[*] Package manager: pnpm (pnpm-lock.yaml)

[*] Checking installed TanStack packages against 42 known-compromised versions…

[*] Checking worm-propagated secondary victims (Mini Shai-Hulud)…
[*]   Packages: @mistralai, @opensearch-project, @draftlab, @draftauth,
[*]   @dirigible-ai, safe-action, cmux-agent-mcp, nextmove-mcp,
[*]   git-git-git, git-branch-selector, agentwork-cli, ml-toolkit-ts,
[*]   wot-api, cross-stitch, ts-dna

[*] Scanning lockfile for known-compromised versions (pnpm-lock.yaml)…
[✓] No compromised versions in lockfile

[*] Checking for persistence artifacts (payload files, hooks, services, C2)…
[✓] No malicious author commits in git history

───────────────────────────────────────────────────────────────
[✓] No compromise detected.

───────────────────────────────────────────────────────────────
  Prevent future supply-chain attacks

  Run with --install-alias to add a pm() shell function that wraps
  every npm/pnpm/yarn/bun install through Aikido's safe-chain scanner.
  safe-chain blocks packages younger than 48 hours and flags known-bad
  versions before they touch node_modules.

    ./check-tanstack-compromise.sh --install-alias
```

## safe-chain alias

Prevent future supply chain attacks by wrapping your package manager with [Aikido's safe-chain](https://github.com/AikidoSec/safe-chain):

```bash
bash check-tanstack-compromise.sh --install-alias
```

This adds a `pm()` shell function that routes `npm`/`pnpm`/`yarn`/`bun` through `safe-chain`, blocking packages younger than 48 hours and flagging known-bad versions.

## Test coverage

The integration Dockerfile creates synthetic fixtures only. It does not download real compromised packages.

The main fixture asserts all 33 detection messages fire across package manifests, lockfiles, persistence artifacts, workflows, git history, source IOCs, payload filenames, AI tool configs, and remediation output:

```bash
docker build -f integration.Dockerfile -t tanstack-check-test .
```

The Docker build also includes targeted regression coverage for:

- `package-lock.json` v3 entries where the package name and compromised version appear on separate lines.
- Yarn v1 lockfile entries where the package selector and compromised `version` appear on separate lines.
- Hash-mismatched `router_init.js` payload filenames returning exit code `1`.
- Home-level Claude Code `SessionStart` hooks even when a clean project-level `.claude/settings.json` exists.

After building, the image command can be run directly:

```bash
docker run --rm tanstack-check-test
```

## References

- [GHSA-g7cv-rxg3-hmpx](https://github.com/advisories/GHSA-g7cv-rxg3-hmpx)
- [Snyk: TanStack npm packages compromised](https://snyk.io/blog/tanstack-npm-packages-compromised/)
- [StepSecurity: Mini Shai-Hulud deep dive](https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem)

