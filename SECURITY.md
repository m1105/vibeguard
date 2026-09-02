# Security & Sensitive-Data Policy ／ 安全與機敏資料政策

_English first, 中文在後半。_

## 1. What this tool is — and is not

VibeGuard is an **advisory** scanner. Its findings are leads, not verdicts, and it produces false positives by design (single-file view, regex rules, probabilistic LLM layer). Details and the correct workflow are at the top of [`README_EN.md`](README_EN.md). Do not use it as a compliance gate or as proof that code is secure.

## 2. Data flow — what leaves the machine

| Layer | Runs where | Sends anything? |
|---|---|---|
| L1 secrets / entropy / config / AI patterns | locally, in the plugin worker | no |
| L2 SAST regex, L3 local endpoint regex | locally | no |
| LLM review (optional, can be switched off) | your local `claude` / `codex` / `gemini` CLI → that vendor's API | **yes — one redacted file per call** |
| Panel, dashboard, notifications, storage | locally (`127.0.0.1` for the dashboard) | no |
| "Open issue" button | your local `gh` CLI → GitHub | **yes — only when you click** |

Before any content goes to the LLM, `shield/redaction.mjs` replaces every value matched by the secret rules and every sensitive assignment value with `VIBEGUARD_REDACTED_SECRET`. The system prompt treats all file content as untrusted data. Only the single file being scanned is sent; the child process is started with `cwd` at that repo's root and receives the prompt on stdin (never on the command line).

Code snippets shown in the panel (±1 line around each hit) go through the same redaction.

## 3. Credentials and local state

Everything below lives in the **state directory `~/.config/vibeguard/`** (mode `0700`, files `0600`; override with `VIBEGUARD_STATE_DIR`). It is **never written into the plugin directory**: an installed plugin's directory is a content-hash snapshot that Orca verifies file by file before starting the worker and before loading the panel, so any write there breaks the plugin after the next Orca restart. The same names are also listed in `.gitignore` for the developer deploy folder.

| File | Content | Sensitivity |
|---|---|---|
| `.llm-token` | Claude long-lived token from `claude setup-token` | **credential** — `0600`; read before each scan; passed only as `CLAUDE_CODE_OAUTH_TOKEN` to the `claude` process; never logged, never embedded in the panel |
| `.dash-token`, `dashboard-url`, `api-url` | 32-hex random token for the local dashboard API, and the two URLs that carry it | local auth secret; the developer-mode panel embeds it, the installed static panel reads it at click time via `$(cat …)` in the shell so the committed panel file contains no token |
| `.notify-state`, `.llm-state`, `.llm-scan-state`, `.locale`, `.notify-open-dashboard` | `on`/`off`, `framework:model`, locale id | plain settings, not sensitive |
| `.vibeguard-learned.json` (in each scanned repo) | rule + relative path + finding title | committed on purpose; contains finding titles, no code |

The dashboard server: binds `127.0.0.1` only, requires the token on every request, rejects any request whose `Host` is not `127.0.0.1:<port>` (DNS rebinding) or whose `Origin` is not same-origin (CSRF), and sends no CORS headers.

## 4. Threat model of the panel ↔ terminal bridge

Panel buttons send text into terminals. Findings originate from **untrusted input** (scanned files, LLM output), so:

- every field is passed through `clean()` / `cleanField()` (control characters, newlines and ESC stripped; length capped) before it reaches a terminal;
- the worker only acts on findings that exist in its own memory (`rule + target + line` must match) — a forged request cannot make it send arbitrary text;
- shell commands are single-quoted (`sq()`) and use the agent TUI's `!` local-shell mode; when the terminal is not recognizably an agent, messages are placed in the input box with `enter: false`;
- the worker never falls back to the *focused* terminal for fix/issue actions (it could belong to another project);
- `vibeguard.scanFile` refuses paths outside a git repository.

## 5. Rules for this repository (contributors, including AI agents)

**No sensitive data anywhere in the tree — not in code, comments, docs, issues, tests or commit messages.**

- **No committed file may contain a string that matches any of VibeGuard's own secret rules**, no matter how fake it looks. GitHub's push protection and secret scanning match on shape alone: a sequential fake such as `AIzaSyA1234567890abcdef…` still produced a public "leaked secret" alert, and a Stripe-shaped fixture was rejected at push time. Test fixtures are therefore assembled at runtime, e.g. `fx('sk-ant-', 'a1b2c3…')` where `fx` joins its parts, so the shape only exists in memory. The only two allowed literals are the AWS documentation example `AKIAIOSFODNN7EXAMPLE` (allow-listed by GitHub itself) and a bare PEM header with no body. Values should still be obviously fake (`FAKE`, `EXAMPLE`, alphabet runs) and hosts `example.com`-style.
- No private absolute paths (`/Users/<name>/…`, `/home/<name>/…`, `C:\Users\…`), no personal e-mail addresses, no names of private projects or customers.
- `panel.html` is a build artifact; only the empty template may be committed (`git checkout panel.html` before committing if the worker rewrote it).
- These rules are enforced by `test/repo-hygiene.test.mjs`, which is part of `npm test` and scans every file that would be committed (tracked + untracked-not-ignored) with the project's own secret rules.

## 6. Reporting a vulnerability

Open a GitHub issue titled `[security] …` with reproduction steps. Do **not** include real secrets in the report. If the problem involves data leaving the machine (redaction gap, prompt-injection path into a terminal, dashboard auth bypass), say so in the title so it is triaged first.

---

## 中文

### 1. 這是什麼、不是什麼

VibeGuard 是**提醒**型掃描器：結果是線索不是判決，而且**會誤報**（單檔視角、regex 規則、機率性的 LLM 層），這是架構使然。正確用法見 [`README.md`](README.md) 最上方。請勿把它當合規閘門，也別把「面板是綠的」當成程式碼安全的證明。

### 2. 資料流：什麼會離開機器

| 層 | 在哪跑 | 會送出東西？ |
|---|---|---|
| L1 密鑰／熵／設定／AI 模式 | 本機 worker | 否 |
| L2 SAST regex、L3 本地端點 regex | 本機 | 否 |
| LLM 審查（可選、可關） | 你本機的 `claude`／`codex`／`gemini` CLI → 該廠商 API | **是——每次一個脫敏後的檔案** |
| 面板、dashboard、通知、storage | 本機（dashboard 只綁 `127.0.0.1`） | 否 |
| 「開 Issue」按鈕 | 你本機的 `gh` → GitHub | **是——只在你按下時** |

送 LLM 前，`shield/redaction.mjs` 把密鑰規則命中的值與敏感賦值的值一律換成 `VIBEGUARD_REDACTED_SECRET`；system prompt 把檔案內容當不可信資料；一次只送被掃的那一個檔；子行程 cwd 設在該 repo 根，prompt 走 stdin 不進命令列。面板上的代碼片段（命中行 ±1）也經過同樣脫敏。

### 3. 憑證與本機狀態

下列檔案都在**狀態目錄 `~/.config/vibeguard/`**（目錄 `0700`、檔案 `0600`；可用 `VIBEGUARD_STATE_DIR` 改位置），**絕不寫進插件目錄**：安裝版的插件目錄是內容雜湊快照，Orca 在 worker 起動與面板載入前逐檔驗證，寫任何東西進去 = Orca 重啟後插件載不起來。同名檔案也列在 `.gitignore`（給開發者部署資料夾用）。

| 檔案 | 內容 | 敏感度 |
|---|---|---|
| `.llm-token` | `claude setup-token` 產生的長期 token | **憑證**——`0600`；每次掃描前讀；只以 `CLAUDE_CODE_OAUTH_TOKEN` 傳給 `claude` 子行程；不記 log、不嵌進面板 |
| `.dash-token`、`dashboard-url`、`api-url` | 本機 dashboard API 的 32 hex 隨機 token，以及帶著它的兩個 URL | 本機認證密鑰；開發者模式面板會內嵌，安裝版靜態面板在按下按鈕時由 shell 以 `$(cat …)` 讀取，commit 的面板檔本身不含 token |
| `.notify-state`、`.llm-state`、`.llm-scan-state`、`.locale`、`.notify-open-dashboard` | `on`／`off`、`框架:模型`、語系 id | 一般設定，不敏感 |
| `.vibeguard-learned.json`（在每個被掃 repo） | rule + 相對路徑 + finding 標題 | 刻意進 git；只有標題沒有程式碼 |

dashboard server：只綁 `127.0.0.1`、每個請求都要 token、`Host` 不是 `127.0.0.1:<port>` 一律拒（防 DNS rebinding）、帶 `Origin` 必須同源（防 CSRF）、不發任何 CORS 頭。

### 4. 面板 ↔ 終端橋接的威脅模型

面板按鈕會把文字送進終端，而 finding 來自**不可信輸入**（被掃檔案、LLM 回傳），所以：

- 每個欄位送進終端前都經 `clean()`／`cleanField()`（清控制字元、換行、ESC，並限長）；
- worker 只對「記憶體裡確實存在」的 finding 動作（`rule + target + line` 必須對上），偽造請求不能讓它送任意文字；
- shell 指令一律單引號跳脫（`sq()`）並走 agent TUI 的 `!` 本機 shell 模式；認不出是 agent 的終端，訊息只放輸入框（`enter: false`）；
- 修復／開 issue 絕不落回「目前 focus 的終端」（可能是別的專案的 agent）；
- `vibeguard.scanFile` 拒絕 git repo 外的路徑。

### 5. 本 repo 的規則（所有貢獻者，含 AI agent）

**樹裡任何地方都不得有機敏資料——程式碼、註解、文件、issue、測試、commit 訊息都算。**

- **會 commit 的檔案裡不得出現任何符合 VibeGuard 自家密鑰規則形狀的字串**，不管看起來多假。GitHub 的 push protection 與 secret scanning 純看形狀：`AIzaSyA1234567890abcdef…` 這種連號假值照樣開出公開「外洩」警報，Stripe 形狀的 fixture 直接被拒推。所以測試 fixture 一律執行期組合，例如 `fx('sk-ant-', 'a1b2c3…')`（`fx` 把片段接起來），形狀只存在記憶體裡。唯二可用的字面值：AWS 官方文件範例 `AKIAIOSFODNN7EXAMPLE`（GitHub 自己放行）與沒有內容的純 PEM 標頭。值本身仍要一眼假（`FAKE`、`EXAMPLE`、連續字母），主機名用 `example.com`。
- 不得有私人絕對路徑（`/Users/<名字>/…`、`/home/<名字>/…`、`C:\Users\…`）、個人信箱、私人專案或客戶名稱。
- `panel.html` 是產物，只能 commit 空模板（worker 改寫過就先 `git checkout panel.html`）。
- 以上由 `test/repo-hygiene.test.mjs` 強制執行——它是 `npm test` 的一部分，用本專案自己的密鑰規則掃全部「會進版控」的檔案（已追蹤 + 未追蹤但未被 ignore）。

### 6. 回報漏洞

開 GitHub issue，標題以 `[security]` 開頭，附重現步驟；**不要**在回報裡貼真密鑰。若問題涉及資料外流（脫敏漏洞、prompt injection 進終端的路徑、dashboard 認證繞過），請在標題註明以便優先處理。
