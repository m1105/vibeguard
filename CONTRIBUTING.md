# Contributing ／ 貢獻指南

_English first, 中文在後半。The rules apply to humans and AI agents alike (see also [`AGENTS.md`](AGENTS.md))._

## Ground rules

1. **Zero dependencies.** Node.js built-ins only; the plugin worker has no `node_modules`. ESM (`.mjs`, `import`/`export`).
2. **`npm test` is the only gate** — there is no lint/build step. It must be fully green before every commit and it includes the sensitive-data gate and the deploy manifest self-check.
3. **TDD.** Write the failing test first, then the implementation, then refactor. Every module in `shield/` has a matching `test/<module>.test.mjs`.
4. **`shield/` is pure.** No Orca imports; all IO (fs, child_process, `host.call`) is injected as parameters. That is why the whole engine is unit-testable without a host.
5. **Never guess Orca host method / event / capability names.** They come from [`docs/01-api-confirmation.md`](docs/01-api-confirmation.md) and are centralized in `shield/host-methods.mjs`. The manifest fields are closed sets.
6. **Fidelity to DeepSec beats "improvements".** Rule ids, regexes, severities and thresholds are ported verbatim from DeepSec's Python; quirks are preserved and pinned by tests. If a behaviour is in doubt, run the original regex with `python3` and match it. Record any deliberate deviation in `docs/02-deepsec-fidelity.md`.
7. **No sensitive data in the tree** — code, comments, docs, tests, commit messages. Fixtures must be obviously fake (`EXAMPLE`, `FAKE`, alphabet runs); families that GitHub push protection matches by shape alone (Stripe `sk_live_`) must be assembled at runtime with `join`. Full policy in [`SECURITY.md`](SECURITY.md); enforced by `test/repo-hygiene.test.mjs`.
8. **Comments explain *why*, briefly.** Chinese or English, follow the surrounding code.

## Panel / dashboard rules (template literals)

`panel-renderer.mjs` and `dashboard.mjs` generate HTML from a template literal. Inside the generated `<script>`:

- **no regex literals** (backslashes get eaten — a `/\/[^/]*$/` once became a `//` comment and killed the whole panel);
- **no backticks, no `${`**; write newlines in strings as `'\\n'`;
- render with `textContent`, never `innerHTML =`;
- never call `location.reload()` (Orca's srcdoc navigation guard breaks the frame and the watchdog kills the panel);
- acceptance: the tests extract the `<script>` and compile it with `new Function`.

## i18n rules

- **Every user-visible string goes into `i18n.mjs`.** No hardcoded UI text in the panel, dashboard, notifications, scan-log notes or agent messages.
- All locales must have the **same key set and the same `{placeholders}`**; values must not contain backticks, `${`, `<` or newlines. `test/i18n.test.mjs` enforces this.
- Multi-line messages are joined in code; the dictionary holds single lines only.
- To add a language: add an object to `LOCALES` and a display name to `LOCALE_NAMES` in `i18n.mjs`; the tests, the panel's language dropdown and the worker's `.locale` validation pick it up automatically. Add the `resolveLocale` mapping if the language tag needs special handling.

## Runtime rules learned the hard way

- **Loading new code = deploy + toggle.** `node scripts/deploy.mjs`, then in Orca Settings turn the plugin off, wait 10 s, turn it on. Never make the worker exit on its own (`process.exit`, uncaught throws): each exit counts against Orca's `maxRestarts = 3`, after which the plugin is marked *errored* and stops receiving events. Never toggle while a deploy is writing.
- **Keep `scripts/deploy.mjs`'s `INCLUDE` in sync with `main.mjs` imports.** `test/deploy.test.mjs` fails otherwise.
- **`panel.html` is a build artifact.** Commit only the empty template (`git checkout panel.html` if the worker rewrote it); `test/repo-hygiene.test.mjs` refuses real findings.
- **Debugging with `scripts/dev-worker.mjs`**: always Ctrl-C it when done. A zombie dev-worker keeps rewriting `panel.html` with old code and makes changes look like they "did nothing".

## Commit messages

`<type>: <description>` with type ∈ `feat, fix, refactor, docs, test, chore, perf, ci`. Describe the *why* (what broke, what was observed) — this repo's history is its incident log.

---

## 中文

### 基本規則

1. **零依賴**：只用 Node.js 內建模組，worker 沒有 `node_modules`。ESM（`.mjs`、`import`/`export`）。
2. **`npm test` 是唯一閘門**——沒有 lint／build。每次 commit 前必須全綠；它包含機敏資料閘門與部署清單自檢。
3. **TDD**：先寫失敗測試，再實作，再重構。`shield/` 每個模組對應一個 `test/<模組>.test.mjs`。
4. **`shield/` 是純函式**：不得 import Orca API；fs／child_process／`host.call` 一律由參數注入。這就是整個引擎不用 host 就能單測的原因。
5. **絕不猜 Orca 的 host method／event／capability 名稱**：以 [`docs/01-api-confirmation.md`](docs/01-api-confirmation.md) 為準，集中在 `shield/host-methods.mjs`；manifest 欄位是閉集合。
6. **忠實移植優先於「改進」**：規則 id、regex、嚴重度、閾值逐字照 DeepSec 的 Python；quirk 如實保留並用測試鎖住。有疑義就用 `python3` 跑原作 regex 比對。刻意偏離的地方記在 `docs/02-deepsec-fidelity.md`。
7. **樹裡不得有機敏資料**——程式碼、註解、文件、測試、commit 訊息都算。fixture 必須一眼假（`EXAMPLE`、`FAKE`、連續字母）。完整政策見 [`SECURITY.md`](SECURITY.md)；由 `test/repo-hygiene.test.mjs` 強制執行。
8. **註解只寫「為什麼」、要短**；中英皆可，跟隨周圍程式碼。

### 面板／dashboard 規則（template literal）

`panel-renderer.mjs` 與 `dashboard.mjs` 用 template literal 產生 HTML。產生出來的 `<script>` 裡：

- **禁 regex 字面值**（反斜線會被吃掉——`/\/[^/]*$/` 曾變成 `//` 註解把整個面板弄掛）；
- **禁反引號與 `${`**；字串裡的換行寫 `'\\n'`；
- 一律 `textContent` 渲染，禁 `innerHTML =`；
- 禁 `location.reload()`（Orca 的 srcdoc 導航攔截會把 frame 打壞，watchdog 判死）；
- 驗收：測試抽出 `<script>` 用 `new Function` 編譯。

### i18n 規則

- **所有使用者看得到的字串都進 `i18n.mjs`**：面板、dashboard、通知、掃描記錄 note、送給 agent 的訊息一律不硬編碼。
- 各語系 **key 集合與 `{佔位符}` 必須完全一致**；值不得含反引號、`${`、`<`、換行。`test/i18n.test.mjs` 會擋。
- 多行訊息在程式碼 join；字典只放單行。
- 新增語言：在 `i18n.mjs` 的 `LOCALES` 加一個物件、`LOCALE_NAMES` 加顯示名；測試、面板下拉、worker 的 `.locale` 驗證會自動納入。語言標籤需要特殊對應時補 `resolveLocale`。

### 執行期規則（踩坑換來的）

- **換碼 = deploy + toggle**：`node scripts/deploy.mjs`，然後到 Orca 設定頁把插件關掉、等 10 秒、再開。絕不讓 worker 自行退出（`process.exit`、未捕捉的 throw）：每次退出都算進 Orca 的 `maxRestarts = 3`，用完插件標 *errored*、事件全丟。deploy 寫檔中絕不 toggle。
- **`scripts/deploy.mjs` 的 `INCLUDE` 要跟 `main.mjs` 的 import 同步**，否則 `test/deploy.test.mjs` 會失敗。
- **`panel.html` 是產物**：只 commit 空模板（worker 改寫過就 `git checkout panel.html`）；`test/repo-hygiene.test.mjs` 拒絕含真實 findings 的版本。
- **用 `scripts/dev-worker.mjs` 除錯**完務必 Ctrl-C：殭屍 dev-worker 會用舊碼一直重寫 `panel.html`，造成「改了沒效」的假象。

### Commit 訊息

`<type>: <描述>`，type ∈ `feat, fix, refactor, docs, test, chore, perf, ci`。寫「為什麼」（壞在哪、觀察到什麼）——這個 repo 的歷史就是它的事故紀錄。
