# 03 — Development approach, testing method, and pitfalls found in the real Orca runtime

_中文: [`03-development-and-testing.md`](03-development-and-testing.md)_

This document answers three questions: **how the plugin was built**, **how we verify it actually works**, and **where the next person (human or AI agent) is most likely to trip**. The single source of truth for API names is [`01-api-confirmation.md`](01-api-confirmation.md) (Chinese); for rules it is [`02-deepsec-fidelity.en.md`](02-deepsec-fidelity.en.md). Neither is repeated here.

## 1. Approach: porting DeepSec to an Orca plugin

### 1.1 Why a port rather than a rewrite

[DeepSec](https://github.com/Unclecheng-li/DeepSec) already had a curated rule base (secret formats, entropy thresholds, injection patterns, endpoint semantics) and scan orchestration (skip lists, dedup, redaction). Those are *knowledge*, not code style — rewriting them means re-making mistakes the original author already fixed. Hence:

- **The rule layer is ported verbatim**: every regex, severity, threshold and rule id is checked against the Python source (`rules/patterns.py`, `rules/sast.py`, `rules/ai_audit.py`, `scanner.py`).
- **Quirks are ported too**: e.g. DOMPurify's negative lookahead is defeated by whitespace backtracking; the assignment regex needs ≥ 1 character before the keyword (bare `apiKey=` does not match); env-var references are judged on the whole line. They look like bugs, but "fixing" them would diverge from the original and make cross-validation impossible. They are pinned by tests marked `fidelity quirk`.
- **What is deliberately not ported is written down**: Python AST taint, Tree-sitter, agent_security, supply_chain (docs/02 #15). Semantic judgement is delegated to the agent CLI the user already has — more accurate and far less work than moving an AST engine to JS, and a natural fit for Orca users who already run Claude/Codex.

### 1.2 Layers and pure functions

```
shield/            pure engine: no Orca imports; all IO injected as parameters
  l1-secrets.mjs   11 secret rules
  l1-entropy.mjs   sensitive assignment + Shannon entropy
  l1-rules.mjs     13 CONFIG + 20 AI_PATTERN rules
  l2-sast.mjs      16 injection regexes
  l3-local.mjs     4 endpoint-semantics rules (off by default)
  l23-llm.mjs      redact → prompt → spawn CLI → parse JSON → normalize
  redaction.mjs    redaction before LLM
  scanner.mjs      single-file orchestration, skip lists, dedup
  finding.mjs      Finding constructor, dedup, content fingerprint (identity)
  learning.mjs     false-positive learning (.vibeguard-learned.json)
  watcher.mjs      fs.watch + debounce + concurrency gate
  host-methods.mjs Orca host method name constants (the only place to rename)
main.mjs           worker glue: events, commands, notification throttling, storage, panel baking, doAction API
panel-renderer.mjs the panel (generated HTML with data inlined)
dashboard.mjs      live dashboard page (served by panel-server)
panel-server.mjs   127.0.0.1 HTTP (token auth)
i18n.mjs           UI dictionary (four locales)
```

"Pure" is not a style preference; it is the **test strategy**: `shield/` is unit-testable without Orca, and `main.mjs` is driven by a fake `orca` object (recording every `host.call`) with injected fs / spawn / CLI doubles. That is why 383 tests run in about 1.5 s with no external services.

### 1.3 Why the panel looks the way it does (a design overturned by measurement)

The original plan was a panel polling a local HTTP server. Measured reality: Orca's panel shell gives the iframe a CSP of `connect-src 'none'` — **the panel cannot fetch anything**. So it became "generated": after every scan the worker inlines the findings into `panel.html` (atomic rewrite), and the panel re-reads it from disk whenever it opens. Panel actions can only go through Orca's postMessage bridge (three legal actions: `readContext` / `sendText` / `notify`), so every button "borrows the worktree's agent terminal in `!` mode to run a one-line curl against the worker's API". Circuitous, but it is the only route that works inside the sandbox, and the API side is guarded by a token and finding-existence checks.

True live updates come from the 🚀 dashboard: Orca's embedded browser has no such CSP and can poll directly.

## 2. Testing method

### 2.1 One test file per layer

Each `shield/x.mjs` has a `test/x.test.mjs`. Rule tests follow "at least one hit, one non-hit and one boundary case per rule". Threshold rules (entropy 3.8 / 4.5, length 16–180) have exactly-at-threshold cases.

### 2.2 Fidelity verification

When a rule regex is in doubt we **do not guess**: the DeepSec regex is run with `python3 -c` and compared with the JS result; differences caused by engine semantics (e.g. `\w` and Unicode, lookbehind) are recorded in the test comments with the measured outcome. Skip lists, rule ids and severities are compared line by line with docs/02.

### 2.3 Worker wiring tests (`test/main.test.mjs`)

`fakeOrca()` provides `commands.register` / `events.on` / `host.call`; `fakeDeps()` injects readFile / writeFile / spawn doubles / CLI doubles / a clock. Covered: notifications only for not-yet-notified critical/high with a 2-minute cooldown; the three granularities of the ignore file; learned-file writes and post-filtering; panel baking only on "meaningful change" with 5-second throttling; deleted files auto-resolving; LLM toggle and queue-full skipping; every doAction and its anti-forgery check (only findings present in memory); locales (notifications / messages / noteKey); terminal routing (`agentIdentity` and heuristics).

### 2.4 End-to-end (`test/e2e.test.mjs`)

A sample file with an Anthropic key, SQL template interpolation and more goes through scanText → dedup → every field present → redaction contains no real value → panel-server returns 403 without a token.

### 2.5 Artifact acceptance

- **Syntax check of the baked HTML**: the `<script>` is extracted and compiled with `new Function`. This is the formal acceptance test because a backslash in the template literal once baked `/\/[^/]*$/` into a `//` comment, killing the whole panel script (no button responded).
- **Template functions tested in isolation**: `sq()` (shell quoting), `clean()` (sanitizing), `scanBadge()` are pulled out of the HTML by regex and evaluated directly.
- **Dictionary consistency** (`test/i18n.test.mjs`): identical key sets and placeholders across the four locales; no characters that break inlining.
- **Deploy manifest self-check** (`test/deploy.test.mjs`): the INCLUDE list in `scripts/deploy.mjs` must cover every transitive import of `main.mjs`.
- **Sensitive-data gate** (`test/repo-hygiene.test.mjs`): see SECURITY.md.

### 2.6 Manual acceptance (real Orca)

Code tests cannot prove "it actually works inside Orca". The chain verified by hand: save a file with a fake secret → notification within 2 s → panel shows it → the fix message lands in the correct worktree's agent terminal → dismissing removes it within seconds and moves it to Resolved → deleting the file moves it to Resolved automatically. Re-run this chain whenever the event / terminal / panel-baking logic in `main.mjs` changes.

## 3. Pitfalls found in the real Orca runtime (required reading)

Each item below actually happened and took real time to diagnose. CLAUDE.md carries a condensed version for AI agents.

### 3.1 Worker lifecycle

- **The worker starts lazily**: enabling the plugin does not start it; the first manifest-subscribed event (`worktree.created` / `agent.status.changed`) or a manual command does. Subscribing to `agent.status.changed` is therefore not only for agent attribution — it is the "wake the worker whenever an agent moves" mechanism.
- **Idle for 5 minutes → reaped**: keepalive calls `storage.keys` every 4 minutes.
- **Existing worktrees never emit `created`**: after startup, `orca worktree list --json` backfills them. This **must not** be awaited inside `activate` — if the host refreshes during activation, the worker is deactivated the instant activation completes.
- **maxRestarts = 3**: every self-exit counts as a failure; after three the plugin is marked `errored`, all events are dropped, and nothing wakes it — only toggling the plugin in Settings resets the counter. Therefore there is **no `process.exit` anywhere**, the panel's "restart" only shows the toggle instructions, and the crash log goes to `os.tmpdir()` (writing into the plugin directory triggers the dev watcher, which kills the worker mid-activation).
- **New code = deploy + toggle**: `touch`-ing the deploy folder only remounts the panel; it does not load code. Never toggle while a deploy is writing.

### 3.2 Panel

- **Panel watchdog**: Orca's shell sends `orca-panel-ping` periodically; if the panel does not answer `orca-panel-pong` (with the original pingId) within 5 s it is declared unresponsive and suspended — the cause of the "plugin panel stopped responding" black screen.
- **The srcdoc iframe forbids any subsequent navigation**: `location.reload()` and meta refresh do nothing and leave the frame in a broken state where pongs stop. The only update path is worker rewrites `panel.html` → dev watcher → Orca remounts.
- **Bake throttling and "meaningful change"**: baking after every scan while an agent writes at high frequency makes the panel flicker and collide with the watchdog. Bakes happen only when findings / resolved / issues / settings change, merged within 5 s; scan-log-only changes do not bake (a 10-minute liveness bake keeps the heartbeat warning honest).
- **View state in localStorage**: every remount reloads the whole HTML, so scroll position, read set, collapsed sections and language must be persisted by the page.
- **Content fingerprints**: if a finding's identity included the line number, an agent inserting a few lines at the top would mark everything "resolved" and everything "NEW". The identity is `rule + target + title + hit-line content`, with a sequence number for duplicates.

### 3.3 Terminal routing

- Older Orca APIs have no terminal identity field (only title / preview). **"No agent features recognized" ≠ "it is a shell"** — an idle agent has no spinner and its title may be a task name. A bare command with auto-Enter sent to an agent goes straight into the conversation. So shells are treated as non-existent: every command uses the agent terminal's `!` local-shell mode (hitting a real shell only yields "event not found", harmless); when the agent cannot be recognized, messages are placed in the input box only.
- Orca ≥ 1.4.193 exposes `agentIdentity` in `terminal list` — definitive; used when present.
- `terminal.sendText` can only reach terminals of the *focused* worktree; cross-worktree sends must use the `orca terminal send --terminal <handle>` CLI. Fix / issue actions never fall back to the focused terminal (a fix for project A once landed in project B's agent).

### 3.4 LLM child process

- The GUI-forked worker has a thin PATH: CLIs use candidate paths (`/usr/local/bin`, `/opt/homebrew/bin`) and run through `zsh -lc` to load the user's environment.
- After a failed spawn candidate Node still emits `close(-2)`; a `failed` flag prevents a false rejection.
- `cwd` must be the scanned repo's root: claude / codex directory trust is keyed on cwd, and an untrusted deploy folder exits 1.
- A background worker sharing the user's OAuth session fights over the single-use refresh token ("login → works briefly → broken again"). The cure: a long-lived token from `claude setup-token` stored in `.llm-token` and passed as `CLAUDE_CODE_OAUTH_TOKEN`. **Testing `claude -p` from inside a Claude Code session is contaminated by its internal credential channel and proves nothing about the worker**; verify in a clean environment (unset all `CLAUDE*` / `ANTHROPIC*`) + token + `zsh -lc` + repo cwd.
- Concurrency is 1: two claude processes refreshing at once corrupt the session. Running + queued is capped at 4; when full the LLM step is skipped for that scan.
- No automatic fallback to another framework: it would silently burn the user's quota with another vendor; instead the real cause (tail of the output) goes into the scan log.
- claude is pinned to `--max-turns 1`: `claude -p` is an agentic loop that would otherwise browse the repo for minutes; the design is single-file review.

### 3.5 False positives and dogfooding

- The LLM sees one file and reports "guard lives elsewhere" as a vulnerability. The prompt requires "confirmable only across files → severity ≤ medium, confidence ≤ 0.5, description prefixed 'unverified'", and injects the titles already learned as false positives for that file.
- Scanning itself, VibeGuard found three real issues (fix messages auto-submitted unsanitized into a shell, executing line by line; `scanFile` accepting any path, allowing arbitrary files to be read and sent to the LLM; unsanitized finding fields sent to terminals forming a prompt-injection channel) and one template-escaping bug (`\d` eaten into `d` inside the template literal, so line stripping for dismissals never worked). That is why "scan yourself" is a standing acceptance step.
