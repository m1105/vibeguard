# VibeGuard for Orca

> Real-time security guard for AI-generated code — a plugin for [Orca](https://www.onorca.dev)

**中文**: [`README.md`](README.md)

When coding agents (Claude / Codex / Kimi / …) write files in your worktrees, VibeGuard scans them in the background: hardcoded secrets, injection flaws, insecure configuration, and common AI-code mistakes. Findings trigger system notifications and appear in a dedicated panel grouped by **project → agent → file**, with one-click fix (sends "what's wrong / why / how to fix" back to the agent's own terminal) and GitHub issue tracking.

## Features

- **Real-time scanning** — watches every Orca worktree for file changes; scans no matter who wrote the file (any agent or a human)
- **Three detection layers** (see "How it works"): L1 secrets/config/AI patterns, L2 injection SAST, L3 endpoint semantics
- **Three-severity panel** — 🔴 serious (critical/high) vs 🟠 attention (medium/low) sections; click any row to open the file at that line
- **One-click fix** — sends a sanitized problem description back to that worktree's agent terminal
- **GitHub issue tracking** — one click opens an issue (with a `vibeguard-key:` machine marker); the panel tracks open/closed state automatically
- **False-positive learning** — dismissed findings are recorded in `.vibeguard-learned.json`; the LLM is told not to report them again
- **Budget-friendly** — the LLM layer can be turned off entirely (local regex only), or switched to a cheaper framework/model
- **Bilingual panel** — the panel UI follows your system language (中文/English) and can be switched manually

## Installation

> ⚠️ Orca's plugin system is **experimental** (`pluginApi: 1`). APIs may change.

**Option A: Marketplace (recommended)**

1. Orca → `Cmd-,` → **Plugins** → **Marketplaces** → **Add source** → paste this repo's GitHub URL
2. Find **VibeGuard** in the browser → **Install** → consent to capabilities → enable

**Option B: Manual (developers)**

1. `git clone` this repo
2. Orca → Settings → Plugins → install from local path
3. Consent to capabilities and enable

**LLM requirement**: L1/L2 local rules need nothing external. The L3 LLM semantic review needs one of the `claude`, `codex`, or `gemini` CLIs installed (default: `claude` with the `haiku` model; switchable in the panel). If no CLI is available, that layer is skipped silently and local scanning is unaffected.

## Usage

### Automatic scanning

Nothing to do after enabling: any file saved in a worktree triggers a scan (2 s debounce). Critical/high findings raise a desktop notification (each finding notifies once, global 2-minute cooldown).

### Panel (VibeGuard security overview)

- **Filter chips**: All / Serious only / Attention only / ✓ Mark all read / 🔄 Restart worker
- **Each finding row**: title, file:line, layer (L1/L2/L3), confidence, and a plain-language description
- **Row buttons**:
  - 🔧 **One-click fix** — sends the problem back to that worktree's agent terminal (if the terminal isn't clearly an agent, the text is only placed in the input box, never auto-submitted)
  - 📝 **Open issue** — instructs the agent to file a GitHub issue with a `vibeguard-key:` marker; the panel then tracks its state
  - 🙈 **Dismiss** / **Skip this file** — writes to the repo's `.vibeguard-ignore` via a shell command (no AI round-trip, zero tokens)
- **Settings row**:
  - 🔔 **Notifications** — off means it still scans and records, just doesn't pop notifications
  - 🧠 **L3 semantic review** — pick LLM framework (claude/codex/gemini) and model; or turn the LLM layer off entirely (regex only, no AI spend)
  - 🌐 **Language** — panel language (defaults to system language)

### Scan log

The bottom of the panel lists every scan/skip/watch event with timestamps — this is how you know it's actually running.

### `.vibeguard-ignore` (repo root)

```
# Three granularities; takes effect immediately on save
rule_id                          # disable a rule project-wide
rule_id src/config.js            # skip this rule for one file
rule_id src/config.js:42         # dismiss one specific finding
```

Dismissed findings vanish from the list (into the "resolved" section) and are learned into `.vibeguard-learned.json`.

### `.vibeguard-learned.json` (false-positive learning)

Dismissed items are recorded (rule + relative path + title, capped at 100). On later LLM scans of the same file, learned titles are injected into the prompt ("don't report these") and results are filtered again. **This file is meant to be committed** (shareable with your team); add it to `.gitignore` if you don't want that.

### Commands

| Command | Description |
|---|---|
| `VibeGuard: Scan File` | Scan a specific file |
| `VibeGuard: Scan Whole Project` | Walk every supported file in the project |
| `VibeGuard: One-Click Fix` | Fix a specific finding |
| `VibeGuard: Status` | Current status |

## How it works (layered engine)

| Layer | Engine | Cost | Covers |
|---|---|---|---|
| **L1** | Local regex + Shannon entropy | Free, <50 ms, deterministic | 11 secret patterns (AWS/GitHub/Slack/Stripe/Google/npm/Anthropic/OpenAI/JWT/private keys/DB URLs), sensitive assignments + high-entropy strings, insecure config, common AI mistakes |
| **L2** | Local SAST regex | Free | SQL injection, XSS, SSRF, path traversal, command injection, unsafe deserialization, … (16 rules) |
| **L3** | LLM semantic review (your local agent CLI) | Your AI quota | Missing auth/rate-limit/input-validation/error-handling on endpoints — things that need cross-line semantics |

Pipeline: `fs.watch` → 2 s debounce → L1/L2 local scan → **redaction** → (optional) LLM → dedup → notify + storage + panel re-render.

Performance gates: files >500 KB skipped; generated/test/lock files and `node_modules`-style directories always skipped; global LLM concurrency cap of 2.

Design principle: **local first, LLM only for semantics**. Deterministic problems (secret formats, dangerous APIs) are caught by regex — free and unambiguous. Judgement calls (does this endpoint enforce auth?) go to the LLM, which is instructed to downgrade and mark "unverified" anything it cannot confirm from the single file — that keeps false positives down.

## Privacy & sensitive data handling

**What leaves your machine?**

- **L1/L2**: runs entirely on your machine. Nothing is sent anywhere.
- **L3 (optional)**: file content is **redacted first**, then sent to the agent CLI installed on your machine (claude/codex/gemini), whose backend API processes it:
  - Secret values are always replaced with `VIBEGUARD_REDACTED_SECRET` before sending (display masking: ≤8 chars → `***`, otherwise `first4...last4`)
  - A fixed anti-injection system prompt tells the model to treat all file content as untrusted data, never as instructions
  - Only a **single file** is sent per request — never the whole project
- **Notifications/panel**: fully local. Findings live in Orca's plugin storage (on your machine).
- **GitHub issues (only when you click)**: the issue body contains the file path, rule name, and problem description (control characters stripped). **On public repos, check the description for code snippets you don't want public before confirming**; private repos are unaffected.

**Local state files** (inside the plugin directory, plain text, no secrets): `.notify-state` (notification toggle), `.llm-state` (framework:model), `.llm-scan-state` (LLM on/off).

**Declared capabilities** (enforced by Orca's capability gate): `workspace:read`, `terminal:send`, `notifications:show`, `storage`, `events:subscribe`. This plugin has **no** network capability of its own — the only outbound calls are the `gh` CLI (when you click "open issue") and your own agent CLI.

## Credits

This project ports and continues ideas, rules, and engineering decisions from **[DeepSec / VibeGuard](https://github.com/Unclecheng-li/DeepSec)** (VS Code extension + Python core): the L1 rule table, entropy thresholds (3.8/4.5), L2 SAST rules, L3 endpoint checks, scan skip lists, the redaction-before-LLM principle, and the audit JSON schema — all originally from DeepSec (MIT License). Rule-by-rule fidelity analysis: [`docs/02-deepsec-fidelity.md`](docs/02-deepsec-fidelity.md). Attribution details: [`NOTICE`](NOTICE).

What's different: the Python core and Tree-sitter WASM were **not** ported. L2/L3 semantic review is delegated to the agent CLI already installed on your machine (Orca users have Claude/Codex anyway) — more accurate and far less work than porting rules.

## Development

- **Zero dependencies, ESM, `node:test`** — `npm test` runs the full suite (TDD: failing test first)
- Layout: `shield/` (scan engine, pure logic), `main.mjs` (Orca worker glue), `panel-renderer.mjs` / `dashboard.mjs` (panel generators), `panel-server.mjs` (debug HTTP), `test/`, `docs/` (verified Orca plugin API findings)
- The Orca plugin API is experimental — host method/event/capability names are documented in `docs/01-api-confirmation.md`; don't guess
- Contribution rules: [`AGENTS.md`](AGENTS.md)

## Known limitations

- Orca events don't carry "which agent wrote this file" → findings show `unknown` in the agent column
- L3 reviews one file at a time: guards often live elsewhere (middleware/service layer), so LLM findings are **leads to verify**, not verdicts — filing an issue for that repo's agent to investigate is the intended workflow
- Only files inside Orca-managed worktrees are scanned

## License

MIT — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
