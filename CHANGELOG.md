# Changelog

All notable changes to this project. Format loosely follows [Keep a Changelog](https://keepachangelog.com/); versions follow [SemVer](https://semver.org/) with `0.x` meaning the Orca plugin API itself is still experimental.

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
