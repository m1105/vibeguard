# VibeGuard for Orca

> Real-time security **advisories** for AI-generated code — a plugin for [Orca](https://www.onorca.dev)

**中文**: [`README.md`](README.md) ・ Security & sensitive-data policy: [`SECURITY.md`](SECURITY.md) ・ Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md)

When coding agents (Claude / Codex / Kimi / Gemini / …) write files in your Orca worktrees, VibeGuard scans them in the background: hardcoded secrets, injection flaws, insecure configuration, and common AI-code mistakes. Findings raise a desktop notification and appear in a dedicated panel grouped by **project → agent → file**. One click sends "what's wrong / why / how to fix" back to that agent's own terminal, or files a GitHub issue to track it.

---

## ⚠️ Read this first: it is an advisory tool, not a verdict

**Every VibeGuard finding means "please take a look here", not "this is a vulnerability". It produces false positives easily, and that is a property of the architecture, not a bug:**

- **It only sees one file at a time.** In real projects, authentication, authorization, tenant isolation, input validation and rate limiting usually live **somewhere else** — a route's preHandler, a middleware, a shared service/schema layer, framework configuration. Scanning a single file cannot see those guards, so an endpoint that *is* protected can be reported as "missing auth".
- **The local rules are regex.** Deterministic things (secret formats, dangerous API names) are matched reliably; whether a string is a *real* secret, or whether a concatenation is *really* user-controlled, regex cannot tell.
- **The LLM layer is probabilistic.** The prompt instructs it to downgrade anything it cannot confirm from the file to `medium`, confidence ≤ 0.5, and to prefix the description with "unverified"; a learning mechanism remembers false positives you have dismissed. It still guesses wrong.

**How to use it correctly:** treat the panel as a list of *places worth a look*. Start with the 🔴 serious section; if something is fine, dismiss it (it is learned and not reported again); if unsure, "Open issue" and let that repo's agent investigate. **Do not** apply the suggested fix without verifying, and **do not** treat a green panel as proof of safety — it only covers the patterns in the rule set.

---

## Features

- **Real-time scanning** — watches every Orca worktree for file changes (2 s debounce); scans no matter who wrote the file (any agent or a human)
- **Layered engine** (see "How it works"): L1 secrets/config/AI patterns, L2 injection SAST, optional LLM semantic review
- **Severity panel** — 🔴 serious (critical/high) vs 🟠 attention (medium/low); each row shows the hit description and a **±1-line code snippet with secrets masked**; NEW badges; scroll/collapse/read state survives updates
- **One-click fix** — sends a sanitized problem description to the agent terminal **of the worktree the finding belongs to** (the worker routes by worktree; it never targets another project's agent)
- **GitHub issue tracking** — asks the agent to file an issue with `gh issue create` (with a `vibeguard-key:` machine marker); the panel then shows open/closed state
- **Dismiss & false-positive learning** — "Dismiss" / "Skip file" write straight into that repo's `.vibeguard-ignore` (no AI round-trip, zero tokens) and are recorded in `.vibeguard-learned.json` so the LLM stops reporting them
- **Budget-friendly** — the LLM layer can be switched off entirely (local regex only); pick a framework (claude/codex/gemini) and a cheap model; one LLM call at a time with a bounded queue
- **Multilingual** — panel, live dashboard, desktop notifications and the messages sent to agents come in **繁體中文, English, 简体中文, 日本語**; follows the system language by default, switchable in the settings card
- **Zero dependencies** — Node.js built-ins only, no `node_modules`; apart from the agent CLI you installed yourself and `gh`, it never talks to the network

## Installation

> ⚠️ Orca's plugin system is **experimental** (`pluginApi: 1`); APIs may change. Requires Orca ≥ 1.4 and Node.js ≥ 20 (bundled with Orca).

### Option A: Marketplace (regular users)

1. Orca → `Cmd-,` → **Plugins** → **Marketplaces** → **Add source** → paste the raw URL of this repo's `orca-marketplace.json` (or the repo URL)
2. Find **VibeGuard** → **Install** → consent to the capabilities → enable
3. In an installed plugin the 🛡️ VibeGuard sidebar panel is a **static launcher**: explanation, settings, 🔍 scan project, 🚀 open the live page. **Press 🚀 to see results** — the live page in Orca's embedded browser auto-refreshes every 2 s and offers fix / issue / dismiss.
   Why the sidebar cannot show data: Orca verifies the **hash of every file** in an installed plugin's directory (before the worker starts and before the panel loads), so a plugin must not rewrite anything in its own directory — including the `panel.html` that developer mode bakes results into. The panel sandbox also forbids fetch, so the live page is the only place data can be shown live.
4. Turn on "🚀 Open live page on notification" in ⚙️ Settings: when a serious finding raises a notification, the live page opens (or is switched to) automatically.

### Option A′: direct git URL, no marketplace

Orca → `Cmd-,` → **Plugins** → **Install plugin** → choose **Git** and paste:

```
https://github.com/m1105/vibeguard.git#v0.2.0
```

**The `#tag` (or `#commit`) is mandatory** — Orca pins every install to an explicit version and rejects a bare URL. It runs `git clone --depth 1 --branch v0.2.1` on the repo and reads `orca-plugin.json` at the root. To upgrade, install the newer tag. The panel behaves as described above (static launcher + 🚀 live page).

### Option B: developers (clean deploy folder + devPluginPaths, live sidebar panel)

```bash
git clone https://github.com/m1105/vibeguard.git
cd vibeguard
npm test                    # should be all green
node scripts/deploy.mjs     # deploys to ~/orca/plugins-deploy/vibeguard-orca (runtime files only)
```

Then Orca → Settings → Plugins → Development → add the printed folder to **devPluginPaths** → enable.
After every code change: `node scripts/deploy.mjs` → **toggle the plugin off in Settings, wait 10 s, toggle on** (the only safe way to load new code; see "Known limitations").

Why not point at the repo itself: Orca's dev watcher watches the whole folder, and the high-frequency churn of `.git` / editor state kills the worker mid-activation. In the deploy folder the only thing that ever changes is the `panel.html` the worker bakes — which is exactly the mechanism that makes the sidebar panel auto-refresh. Developer mode has no integrity verification, which is why its sidebar panel can show live data — the main difference from an installed plugin.

### LLM requirement (optional)

- **The L1/L2 local rules need nothing external.**
- The LLM review needs one of the `claude`, `codex` or `gemini` CLIs installed (default: `claude` with the `haiku` model, switchable in the panel). If no CLI is available or a call fails, the layer records `LLM_FAILED` with the reason in the scan log; local scanning is unaffected.
- **For Claude, use a long-lived token** (a background worker sharing the OAuth session with your terminal makes both fight over the single-use refresh token, causing repeated logouts):

  ```bash
  claude setup-token            # prints a long-lived token
  mkdir -p ~/.config/vibeguard && chmod 700 ~/.config/vibeguard
  printf '%s' '<token>' > ~/.config/vibeguard/.llm-token
  chmod 600 ~/.config/vibeguard/.llm-token
  ```

  The worker reads it before every scan and runs `claude` with `CLAUDE_CODE_OAUTH_TOKEN`, never touching the keychain. `~/.config/vibeguard/` is where all VibeGuard state lives (see "Privacy & sensitive data"), so upgrades and reinstalls never lose it; the token is only ever passed to the claude framework.

## Usage

### Automatic scanning

Nothing to do after enabling: any file saved in a worktree triggers a scan. Critical/high findings raise a desktop notification (each finding notifies once; global 2-minute cooldown). The "📋 Recent scan log" at the bottom of the panel lists every scan/skip/watch event with timestamps — **that is how you know it is actually running**.

### Panel

- **Summary cards**: serious / attention / resolved counts + "Watching N worktree(s) · last scan HH:MM:SS"
- **Chips**: All / Serious only / Attention only / ✓ Mark all read / 🔍 Scan project / 🚀 Live dashboard / 🔄 Restart (only tells you how to restart safely)
- **Each finding row**: title, hit description, code snippet (▸ marks the hit line), `file:line · layer · confidence`, issue badge
- **Row buttons**:
  - 📄 **Open**: opens the file in the Orca editor (**no line jump** — neither the plugin API nor the CLI supports it, hence the inline snippet)
  - 🔧 **Fix**: sends "file / problem / why dangerous / suggested fix" to that worktree's agent terminal. Auto-submits only when the terminal is recognizably an agent; otherwise the text is placed in the input box for you to confirm
  - 📝 **Open issue**: asks that worktree's agent to file an issue with `gh issue create` (no fix yet); the body ends with a `vibeguard-key:<rule> <path>` marker the panel later matches
  - 🚫 **Skip file** / 🙈 **Dismiss**: appended to that repo's `.vibeguard-ignore`, effective within seconds, and learned into `.vibeguard-learned.json`
- **⚙️ Settings card**:
  - 🔔 **Notifications**: off still scans and logs, only the popup is suppressed
  - 🚀 **Open live page on notification**: when a serious-finding notification fires, the live page is opened (or switched to) as well — strongly recommended for installed plugins, whose sidebar panel does not refresh
  - 🤖 **LLM scan**: off means local regex only, no AI calls at all
  - 🧠 **L3 semantic review**: LLM framework and model dropdowns (claude / codex / gemini)
  - 🌐 **Language**: Auto (system) / 繁體中文 / English / 简体中文 / 日本語. An explicit choice is synced to the worker so notifications and agent messages switch too

How panel actions work under the hood: the panel is an Orca sandboxed iframe (CSP `connect-src 'none'`, no fetch). Every action goes through Orca's postMessage bridge, borrows the worktree's agent terminal in `!` local-shell mode to run a one-line `curl` against the worker's own `127.0.0.1` API (token-authenticated), and the worker executes it. Seeing that command appear in the agent terminal is expected.

### Live dashboard (🚀)

Opens a page in Orca's embedded browser that polls the worker every 2 s, re-renders only when data changed, and calls the API directly (no terminal detour). The URL carries a token (`.dash-token`, in the plugin directory, gitignored); the server binds `127.0.0.1` only and rejects cross-origin requests.

### `.vibeguard-ignore` (repo root, committed)

```
# Three granularities; takes effect on save (the watcher special-cases this file)
rule_id                          # disable a rule project-wide
rule_id src/config.js            # skip this rule for one file
rule_id src/config.js:42         # dismiss one specific finding
```

Dismissed findings vanish from the list (into "Resolved"). Rule ids live in `shield/l1-*.mjs` and `shield/l2-sast.mjs` (e.g. `hardcoded_secret_aws_access_key`, `sast_sql_template_interpolation`; LLM results always use `l3_llm_semantic_review`).

### `.vibeguard-learned.json` (false-positive learning, repo root)

Dismissed items are recorded automatically (rule + relative path + title, capped at 100, oldest dropped first). On later LLM scans of the same file the learned titles are injected into the prompt ("do not report these") and results are filtered again; local-layer findings with the same title in the same file also disappear. **Committed by default** (share the team's judgement); add it to `.gitignore` if you prefer not to.

### Commands (Command Palette)

| Command | Description |
|---|---|
| `VibeGuard: Scan File / 掃描指定檔案` | Scan a specific file (only accepts files inside a git repo) |
| `VibeGuard: Scan Whole Project / 全專案掃描` | Walk every supported file in all watched worktrees (background; LLM respects the toggle and queue cap) |
| `VibeGuard: One-Click Fix / 一鍵修復` | Fix a specific finding (only findings that actually exist in memory) |
| `VibeGuard: Status / 狀態` | Watched worktrees and finding count |

## How it works

| Layer | Engine | Cost | Covers |
|---|---|---|---|
| **L1** | Local regex + Shannon entropy | Free, milliseconds, deterministic | 11 secret patterns (AWS / GitHub / Slack / Stripe / Google / npm / Anthropic / OpenAI / JWT / private keys / DB URLs), sensitive assignments + high-entropy strings, 13 insecure-config rules, 20 common AI-mistake patterns |
| **L2** | Local SAST regex, 16 rules | Free | SQL injection, XSS, SSRF, path traversal, command injection, unsafe deserialization, open redirect, … |
| **L3 (local)** | 4 endpoint-semantics regexes | Free | Endpoints missing auth / rate limit / input validation / error handling. **Off by default** (as in DeepSec) — high false-positive rate |
| **LLM** | Your local agent CLI | Your AI quota | Semantic judgement covering both L2 and L3; fixed JSON output schema; rule always `l3_llm_semantic_review` |

Pipeline: `fs.watch` → 2 s debounce → L1/L2 local scan → **redaction** → (optional) LLM → dedup on `(rule, target, line, evidence)` → content fingerprint (line shifts are not new findings) → notify + storage + panel rebuild.

Performance and quota gates: files > 500 KB skipped; generated / test / lock files and `node_modules`, `.git`, `.omc`, `i18n`-style directories always skipped (list in `shield/scanner.mjs`); **one LLM call at a time**, running + queued capped at 4 (when full, that scan skips the LLM and local results still appear); 600 s per LLM call; claude pinned to `--max-turns 1` (single turn, no repo browsing).

Design principle: **local first, LLM only for semantics**. Deterministic issues are caught by regex — free and stable; only judgement calls go to the LLM, which is told to downgrade and mark "unverified" anything it cannot confirm from the single file (see the warning at the top).

## Privacy & sensitive data

Full policy in [`SECURITY.md`](SECURITY.md). In short:

**What leaves your machine?**

- **L1 / L2 / local L3**: run entirely on your machine; nothing is sent anywhere.
- **LLM layer (optional)**: file content is **redacted first**, then handed to the agent CLI installed on your machine, whose backend API processes it:
  - secret values are replaced with `VIBEGUARD_REDACTED_SECRET` before sending (secret patterns replaced whole; sensitive assignments keep the variable name, only the value is replaced)
  - a fixed anti-injection system prompt: all file content is untrusted data, never instructions
  - only a **single file** per call, never the whole project; the child process runs with cwd at the scanned repo's root (the frameworks' directory-trust mechanism)
- **Panel / notifications / storage**: all local. Findings live in Orca's plugin storage and in `panel.html` (including code snippets, which are also redacted).
- **GitHub issues (only when you click)**: the issue body contains the file path, rule name, description and suggestion (control characters stripped). **On public repos, check the text before confirming.**

**Local state files** (all in `~/.config/vibeguard/`, mode `0600`; **never inside the plugin directory** — an installed plugin's directory is integrity-verified by Orca, and writing into it breaks the plugin after the next Orca restart): `.notify-state`, `.llm-state`, `.llm-scan-state`, `.locale`, `.notify-open-dashboard` (plain settings), `.dash-token`, `dashboard-url`, `api-url` (address and auth token of the local dashboard, bound to `127.0.0.1` only), `.llm-token` (Claude long-lived token — the only external credential). Override the location with the `VIBEGUARD_STATE_DIR` environment variable.

**Declared capabilities** (Orca's capability gate): `workspace:read`, `terminal:send`, `notifications:show`, `storage`, `events:subscribe`. **No network capability** — apart from your own agent CLI and the `gh` calls you trigger, the plugin makes no outbound connections; the dashboard binds `127.0.0.1` only.

**This repository itself**: every file that would be committed (docs, comments, test fixtures included) is gated by `test/repo-hygiene.test.mjs` inside `npm test` — it runs the project's own secret rules over the tree, requires every hit to be obviously fake (`EXAMPLE` / `FAKE` / alphabet runs), forbids private home paths and e-mail addresses, and requires `panel.html` to be the empty template.

## Testing & verification

`npm test` runs everything (Node's built-in `node:test`, zero dependencies): **383 tests** at the time of writing. Every layer has a matching test file (`shield/x.mjs` ↔ `test/x.test.mjs`), plus:

- **Fidelity tests**: rules, thresholds and skip lists are compared line by line with DeepSec's Python original; the original's quirks (e.g. a negative lookahead defeated by whitespace backtracking, bare `apiKey=` not matching) are deliberately preserved and pinned by tests, with `python3` runs of the original regex as the tie-breaker. Rule-by-rule analysis: [`docs/02-deepsec-fidelity.en.md`](docs/02-deepsec-fidelity.en.md) ([中文](docs/02-deepsec-fidelity.md)).
- **End-to-end**: from a sample file with secrets and injections through findings, dedup, redaction and panel-server authentication.
- **Worker wiring tests**: a fake Orca host object drives `activate`, verifying notification throttling, storage, ignore file, learning, panel rebuilds, every doAction, and locales.
- **Syntax check of the baked HTML**: the `<script>` of the panel and dashboard is extracted and compiled with `new Function` (a template-literal backslash once killed the whole panel; this is the formal acceptance test).
- **Dictionary consistency**: the four locales must have identical key sets and placeholders, and values must not contain characters that break inlining.
- **Deploy manifest self-check**: the file list in `scripts/deploy.mjs` must cover every transitive import of `main.mjs` (a missing file makes the worker die three times in a row and the plugin gets marked errored).
- **Sensitive-data gate**: see the previous section.

The development approach and the pitfalls found in the real Orca runtime (worker lifecycle, panel watchdog, terminal routing) are written up in [`docs/03-development-and-testing.en.md`](docs/03-development-and-testing.en.md) ([中文](docs/03-development-and-testing.md)).

## Credits & origin

This project is an **Orca-plugin port and continuation of [DeepSec](https://github.com/Unclecheng-li/DeepSec)** (VS Code extension + Python core, formerly itself named VibeGuard, MIT License). Learned from DeepSec and ported verbatim: the L1 secret / assignment / entropy rules and thresholds (3.8 / 4.5), the CONFIG and AI_PATTERN rules, the 16 L2 SAST regexes, the L3 endpoint checks, the scan skip lists, the dedup semantics, the redact-before-LLM principle, the audit JSON schema and result normalization. Attribution details in [`NOTICE`](NOTICE).

Deliberately **not** ported: Python AST taint analysis, Tree-sitter, agent_security, supply_chain (hallucinated-package detection) — semantic judgement is delegated to the agent CLI you already have; the difference list is in `docs/02`.

## Known limitations

- **False positives** (see the top). LLM findings are leads to verify.
- **The sidebar panel of an installed plugin is static**: Orca hash-verifies every file of an installed plugin, so the plugin cannot rewrite its own `panel.html`; the panel sandbox forbids fetch and no API can trigger a panel remount. Results always live on the 🚀 live page; use the developer install for live data inside the sidebar.
- **No line jump**: Orca plugin API v1 has no openFile action and the CLI has no `--line`; the inline snippet is the substitute.
- **Agent attribution is a guess**: Orca events do not say who wrote a file; the finding is attributed to the agent most recently active in that worktree within 10 minutes (`agent.status.changed`), otherwise `unknown`.
- **Terminal identity is heuristic**: Orca ≥ 1.4.193 exposes `agentIdentity`, which is definitive; older versions only offer title/preview hints. When unsure, fix messages are placed in the input box without auto-submit.
- **Restarting the worker means toggling the plugin**: a worker that exits on its own counts against Orca's consecutive-failure budget (3 strikes → the plugin is marked errored and all events are dropped), so the panel's 🔄 only tells you "Settings → Plugins → off → wait 10 s → on".
- **Only Orca-managed worktrees are scanned**; the `scanFile` command rejects paths outside a git repo (prevents using it to read arbitrary files into an LLM).
- The non-interactive modes of codex / gemini are not verified in every environment; after switching, watch the scan log for `LLM_FAILED`.

## Development

Conventions: [`AGENTS.md`](AGENTS.md) and [`CONTRIBUTING.md`](CONTRIBUTING.md). Highlights: zero dependencies, ESM, `node:test`, TDD (failing test first), `shield/` is pure and must not import Orca APIs, Orca host method names come from [`docs/01-api-confirmation.md`](docs/01-api-confirmation.md) and are never guessed, no regex inside the panel template literal, every UI string goes into the `i18n.mjs` dictionary.

## License

MIT — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
