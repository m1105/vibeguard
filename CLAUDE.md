# CLAUDE.md

Guidance for Claude Code (and any other AI agent) working in this repository. Read this, then [`AGENTS.md`](AGENTS.md) (conventions), [`CONTRIBUTING.md`](CONTRIBUTING.md) (rules with reasons), [`docs/01-api-confirmation.md`](docs/01-api-confirmation.md) (the only source of truth for Orca plugin API names), [`docs/02-deepsec-fidelity.md`](docs/02-deepsec-fidelity.md) (rule fidelity) and [`docs/03-development-and-testing.md`](docs/03-development-and-testing.md) (how it was built, how it is tested, runtime pitfalls).

## One-sentence project

VibeGuard for Orca = a port of [DeepSec](https://github.com/Unclecheng-li/DeepSec)'s real-time security screening into an **Orca plugin**: agents write files → local L1/L2 regex + optional LLM review → desktop notification → panel (worktree → agent → file) → one-click fix back to the agent terminal / GitHub issue. **It is an advisory tool that produces false positives by design** (single-file view); every doc must keep saying so.

## Commands

```bash
npm test                                   # the only gate (node:test; Node ≥25 rejects directory args, auto-discovers test/)
node --test test/scanner.test.mjs          # one file
node --test --test-name-pattern="Shannon"  # by name
npm run check:hygiene                      # sensitive-data gate + deploy manifest self-check only
node scripts/deploy.mjs                    # deploy runtime files to ~/orca/plugins-deploy/vibeguard-orca (then toggle the plugin)
node scripts/dev-worker.mjs                # run the worker against a local host stub (Ctrl-C when done — zombies rewrite panel.html)
git checkout panel.html                    # restore the empty template before committing
```

No lint / build / typecheck. Zero dependencies, ESM, `.mjs`.

## Map

| Path | Role |
|---|---|
| `shield/*.mjs` | scan engine, **pure functions**: never import Orca APIs; fs / child_process / host.call are injected |
| `main.mjs` | the only worker glue (`activate`): fs.watch + debounce, notification throttle, commands, terminal routing, state files, panel baking, `doAction` API |
| `panel-renderer.mjs` | `buildPanelHtml(data)`: panel HTML with findings **and the i18n dictionary inlined**. All panel front-end logic lives in its template literal |
| `dashboard.mjs` | live dashboard page served by `panel-server.mjs` (same dictionary, direct API calls) |
| `i18n.mjs` | UI dictionary for zh-TW / en / zh-CN / ja + `t()` / `resolveLocale()` — **every user-visible string goes here** |
| `panel.html` | **build artifact** rewritten by the worker; commit only the empty template |
| `panel-server.mjs` | 127.0.0.1 HTTP with token; rejects bad Host / cross-origin |
| `orca-plugin.json` | manifest; commands / events / capabilities are closed sets (docs/01 §1–3) |
| `scripts/deploy.mjs` | copies runtime files to the deploy folder; its `INCLUDE` must cover every import of `main.mjs` (`test/deploy.test.mjs`) |
| `test/` | one test file per module + `e2e`, `main` (fake Orca host), `i18n`, `deploy`, `repo-hygiene` |

## Hard rules (each one cost real debugging time)

1. **Never guess Orca host method / event / capability names.** docs/01 only; constants in `shield/host-methods.mjs`.
2. **Fidelity over improvement.** Rules are verbatim DeepSec; quirks are kept and pinned by tests (`fidelity quirk`). Check doubts with `python3` against the original.
3. **Panel/dashboard template literal: no regex literals, no backticks, no `${`, newlines as `'\\n'`, `textContent` only, no `location.reload()`.** Acceptance = tests compile the extracted `<script>` with `new Function`.
4. **All UI strings via `i18n.mjs`**; keys and `{placeholders}` identical across locales; values single-line without `` ` ``, `${`, `<`.
5. **No sensitive data anywhere** (code, comments, docs, tests, commit messages): fixtures obviously fake, no private paths / e-mails / project names. `test/repo-hygiene.test.mjs` enforces it. `panel.html` = empty template only.
6. **Worker must never exit on its own** (`process.exit`, uncaught throws): Orca counts exits toward `maxRestarts = 3`, then marks the plugin errored. Loading new code = deploy + **toggle the plugin in Settings** (off → wait 10 s → on). Crash log goes to `os.tmpdir()`.
7. **Terminal routing is conservative**: treat "no agent features" as unknown, not shell; use `!` local-shell mode; `agentSure=false` → `enter:false`; never fall back to the focused terminal for fix/issue. `agentIdentity` (Orca ≥ 1.4.193) is definitive when present.
8. **Sanitize everything that reaches a terminal** (`cleanField` / `clean`, `sq`); the worker only acts on findings present in memory.
9. **LLM**: redact first (`redaction.mjs`), one call at a time, queue cap 4, cwd = scanned repo root, prompt via stdin, no automatic framework fallback, claude `--max-turns 1`, long-lived token from `.llm-token` when present.
10. **Bake the panel only on meaningful change** (findings / resolved / issues / settings), throttled 5 s; scan-log-only changes never bake.

## Workflow

TDD: failing test → implementation → `npm test` green → (if runtime-facing) deploy + toggle + manual chain in Orca (fake secret file → notification → panel → fix lands in the right agent terminal → dismiss → resolved). Commit messages explain *why*. Before committing: `git checkout panel.html`, `npm test`.

## Known open items

- Agent attribution is inferred (`agent.status.changed`, 10-minute window) — Orca events do not carry the writer's identity.
- `seeds/known-packages.json` is an empty placeholder (supply-chain detection deliberately not ported).
- codex / gemini non-interactive modes are not verified everywhere; watch the scan log for `LLM_FAILED`.
