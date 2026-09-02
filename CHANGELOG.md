# Changelog

All notable changes to this project. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/) with `0.x` meaning the Orca plugin API itself is still experimental.

## [0.2.1] — 2026-09-02 — installed-mode fix (first GitHub install found the integrity trap)

### Fixed
- **Installed plugins broke after an Orca restart.** Orca hash-verifies every file of an installed plugin (Marketplace / git URL) before starting the worker and before loading the panel; 0.2.0 wrote `.dash-token` and rebaked `panel.html` inside that directory, so the next verification failed. All state now lives in `~/.config/vibeguard/` (`VIBEGUARD_STATE_DIR` to override), legacy files in the plugin directory are migrated once, and in installed mode the worker never writes into its own directory.
- Settings and the Claude token no longer vanish on upgrade (each version used to get a fresh hash directory).

### Changed
- **Installed mode: the sidebar panel is a static launcher** (`panel.html` with `static: true`): explanation, settings, 🔍 scan project, 🚀 live page. Panel commands resolve the worker address at click time with `$(cat "$HOME/.config/vibeguard/api-url")`, so the committed file contains no token. The live dashboard is the live UI; the sidebar cannot refresh itself (CSP `default-src 'none'`, no remount API — see docs/01 §16). Developer mode (devPluginPaths) keeps the live sidebar panel.
- New setting **"🚀 Open live page on notification"** (`.notify-open-dashboard`): the worker runs `orca goto` on the live page when a serious-finding notification fires. Notification body now points to the 🚀 button.
- Heartbeat banner wording no longer claims the worker died when the panel is merely a stale snapshot.
- `orcaCli` is injectable for tests; four unused dictionary keys removed.


## [0.2.0] — 2026-09-02 — first open-source release

### Added
- **Multilingual UI**: panel, live dashboard, desktop notifications, scan-log notes and the messages sent to agents in 繁體中文 / English / 简体中文 / 日本語 (`i18n.mjs`, single shared dictionary). Auto-detects the system language; explicit choice in the settings card is synced to the worker (`.locale`).
- **Finding identity by content fingerprint** (`rule + target + title + hit line`): inserting lines above a finding no longer marks it resolved and re-adds it as NEW; resolved history is de-duplicated on load.
- **Scan log persisted** to plugin storage (survives worker restarts) and **severity-aware scan badges** (🔴 only when critical/high; 🟠 for medium; 🟡 for low).
- **Terminal identity from Orca's `agentIdentity` field** (Orca ≥ 1.4.193) as a definitive signal, ahead of the title/preview heuristics.
- **Sensitive-data gate** in `npm test` (`test/repo-hygiene.test.mjs`): scans every file that would be committed with the project's own secret rules, forbids private paths / e-mails, and requires `panel.html` to be the empty template.
- **Deploy manifest self-check** (`test/deploy.test.mjs`): the deploy INCLUDE list must cover every transitive import of `main.mjs`.
- Documentation: bilingual README with a prominent false-positive warning, `SECURITY.md`, `CONTRIBUTING.md`, `NOTICE` with DeepSec attribution, `docs/02` in English, `docs/03` on development & testing method and runtime pitfalls (中/EN), sanitized `CLAUDE.md`.

### Changed
- Manifest command titles are bilingual (English / 中文); description states the advisory nature.
- Panel: notification toggle and LLM picker now go through the worker API like the other settings (they previously depended on a shell terminal the worker no longer reports, so they silently failed to persist); the "Attention" section is expanded by default.
- `package.json` carries license / repository metadata; version 0.2.0 kept in sync with the manifest by test.

### Removed / sanitized for open source
- Internal hand-off notes, issue specs and private project names removed from the tree and test fixtures; DB-URL fixtures made obviously fake.

## [0.1.0] — 2026-08-31 — internal

Initial Orca plugin: L1/L2/L3 port of DeepSec rules, LLM review via local agent CLIs with redaction, generated panel with fix / issue / dismiss actions, false-positive learning, live dashboard, LLM on/off switch, whole-project scan.
