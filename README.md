# VibeGuard for Orca

> AI 生成代碼的即時安全**提醒** —— [Orca](https://www.onorca.dev) 插件

**English**: [`README_EN.md`](README_EN.md) ・ 安全與機敏資料政策：[`SECURITY.md`](SECURITY.md) ・ 貢獻：[`CONTRIBUTING.md`](CONTRIBUTING.md)

當 Claude / Codex / Kimi / Gemini 等 coding agent 在你的 Orca worktree 寫檔時，VibeGuard 在背景即時掃描：硬編碼密鑰、注入類漏洞、不安全設定、AI 常見錯誤模式。發現問題時跳系統通知，並在專屬面板按「專案 → agent → 檔案」分層呈現；一鍵把「錯在哪／為什麼／怎麼改」送回該 agent 的 terminal 讓它自己修，或開 GitHub issue 追蹤。

---

## ⚠️ 請先讀：這是提醒工具，不是判決

**VibeGuard 的每一筆結果都是「請你去看一眼」的線索，不是「這裡有漏洞」的結論。它很容易誤報，這是架構使然，不是 bug：**

- **它一次只看一個檔案。** 認證、權限、租戶隔離、輸入校驗、限流等防護，在真實專案裡經常寫在**別的地方**（路由註冊的 preHandler、中介層、共用的 service／schema 層、框架設定）。只掃單一檔案，看不到那些防護存在，所以會把「其實有守衛」的端點報成「缺認證」。
- **本地規則是 regex。** 密鑰格式、危險 API 名稱這類**確定性**的東西 regex 抓得準；但「這個字串是不是真密鑰」「這個拼接是不是真的可被使用者控制」regex 無法判斷，會有假陽性。
- **LLM 層是機率性的。** 我們用固定 prompt 要求它「無法從本檔確認的一律降級為 medium、信心 ≤0.5、描述開頭標『未查證』」，並用誤報學習機制吸收你已經確認過的誤報，但它仍會猜錯。

**正確用法**：把面板當成「值得看一眼的地方」清單。🔴 嚴重區優先看；看完覺得沒問題就按「忽略」（會學起來不再報）；不確定就按「開 Issue」讓該 repo 的 agent 去查證。**不要**未經查證就照著修法改程式碼，也**不要**因為面板是綠的就認定程式碼安全——它只涵蓋規則庫裡有的模式。

---

## 功能特色

- **即時掃描**：監聽所有 Orca worktree 的檔案變動（debounce 2 秒），誰寫的都掃（任何 agent 或手動編輯）
- **分層引擎**（見下方「運作原理」）：L1 密鑰／設定／AI 模式、L2 注入類 SAST、（可選）LLM 語意審查
- **分級面板**：🔴 嚴重（critical/high）與 🟠 注意（medium/low）分區；每列顯示命中說明與 **±1 行代碼片段（密鑰已遮蔽）**；未讀 NEW 徽章；捲動／折疊／已讀狀態跨更新保留
- **一鍵修復**：把消毒過的問題描述送回**該 finding 所屬 worktree** 的 agent terminal（worker 依 worktree 路由，不會誤送別的代理）
- **GitHub issue 追蹤**：一鍵請 agent 用 `gh issue create` 開 issue（含機器標記 `vibeguard-key:`），面板自動顯示「已開／已完成」
- **忽略與誤報學習**：「忽略這筆」「此檔免檢」直接寫進該 repo 的 `.vibeguard-ignore`（不經過 AI、不耗 token），並記進 `.vibeguard-learned.json` 讓 LLM 之後別再報
- **省額度**：LLM 層可整個關掉（只跑本地 regex）；可選框架（claude／codex／gemini）與便宜模型；LLM 一次只跑一個、排隊上限有保護
- **多國語系**：面板／即時 dashboard／桌面通知／送給 agent 的訊息支援 **繁體中文、English、简体中文、日本語**，預設跟隨系統語言，可在設定卡切換
- **零依賴**：純 Node.js 內建模組，無 node_modules；除了你自己安裝的 agent CLI 與 `gh`，不主動連外

## 安裝

> ⚠️ Orca 插件系統目前是**實驗性**（`pluginApi: 1`），API 可能變動。需要 Orca ≥ 1.4、Node.js ≥ 20（Orca 內建）。

### 方法一：Marketplace（一般使用者）

1. Orca → `Cmd-,` → **Plugins** → **Marketplaces** → **Add source**，貼上本 repo 的 `orca-marketplace.json` 原始網址（或 repo URL）
2. 在瀏覽裡找到 **VibeGuard** → **Install** → 同意 capabilities → 啟用
3. 面板：側邊欄的 🛡️ VibeGuard。它是**快照**：worker 每次掃描後重寫 `panel.html`，關閉再開面板即可看到最新（Marketplace 安裝沒有 dev watcher，面板不會自動刷新；要真即時請按面板的 🚀 開內嵌 dashboard）

### 方法一之二：不經 Marketplace，直接貼 git URL

Orca → `Cmd-,` → **Plugins** → **Install plugin** → 選 **Git**，貼：

```
https://github.com/m1105/vibeguard.git#v0.2.0
```

**`#` 後面的 tag 或 commit 是必填**（Orca 要求安裝釘在明確版本；只貼 URL 會被拒絕）。Orca 會 `git clone --depth 1 --branch v0.2.0` 這個 repo，讀根目錄的 `orca-plugin.json`。要升級就重新安裝新的 tag。

### 方法二：開發者（乾淨部署資料夾 + devPluginPaths，面板自動更新）

```bash
git clone https://github.com/m1105/vibeguard.git
cd vibeguard
npm test                    # 應全綠
node scripts/deploy.mjs     # 佈署到 ~/orca/plugins-deploy/vibeguard-orca（只放 runtime 檔）
```

然後 Orca → Settings → Plugins → Development → 把上面印出的資料夾加進 **devPluginPaths** → 啟用。
之後每次改碼：`node scripts/deploy.mjs` → **到設定頁把插件關掉、等 10 秒、再開**（這是唯一安全的換碼方式，見「已知限制」）。

為什麼不直接指向 repo：Orca 的 dev watcher 會盯著整個資料夾，repo 裡 `.git`／編輯器狀態的高頻變動會在 activation 中途把 worker 殺掉；部署資料夾裡唯一會變的就是 worker 自己烤的 `panel.html`，這正是「面板自動更新」的機制。

### LLM 需求（可選）

- **L1／L2 本地規則不需要任何外部服務。**
- LLM 語意審查需要本機已安裝 `claude`、`codex` 或 `gemini` CLI 其中之一（預設 `claude` + `haiku` 模型，可在面板切換）。沒有可用 CLI 或呼叫失敗時，該層記 `LLM_FAILED` 並在掃描記錄顯示原因，本地掃描不受影響。
- **Claude 建議用長期 token**（背景 worker 與你終端的 OAuth session 共用時會互相搶 refresh token，造成反覆登入失效）：

  ```bash
  claude setup-token            # 印出一個長期 token
  # 把它存到「插件安裝目錄」的 .llm-token（不是 repo！）
  printf '%s' '<token>' > ~/orca/plugins-deploy/vibeguard-orca/.llm-token
  chmod 600 ~/orca/plugins-deploy/vibeguard-orca/.llm-token
  ```

  worker 每次掃描前讀它，以 `CLAUDE_CODE_OAUTH_TOKEN` 環境變數執行 `claude`，完全不碰 keychain。此檔已在 `.gitignore`，且只給 claude 框架，不會外流。

## 使用方法

### 自動掃描

啟用後不需任何操作：任何 agent 在 worktree 存檔就觸發掃描。發現 critical/high 問題時跳桌面通知（每筆問題只叫一次，全域 2 分鐘冷卻）。面板底部「📋 最近掃描記錄」列出每次掃描／跳過／監聽事件與時間戳——**「有沒有在掃」看這裡，不用猜**。

### 面板

- **摘要卡**：嚴重／注意／已修正數量 + 「監聽 N 個 worktree · 最後掃描 HH:MM:SS」
- **過濾 chips**：全部／僅嚴重／僅注意／✓ 全部已讀／🔍 掃全專案／🚀 即時 dashboard／🔄 重啟（只會告訴你怎麼安全重啟）
- **每列 finding**：標題、命中說明、代碼片段（▸ 標記命中行）、`檔案:行 · 層級 · 信心度`、issue 徽章
- **列按鈕**：
  - 📄 **開檔**：在 Orca 編輯器開啟該檔（**無法跳到行號**——Orca 插件 API 與 CLI 都不支援，所以片段直接顯示在面板上）
  - 🔧 **修復**：把「檔案／問題／為什麼危險／建議修法」送到該 worktree 的 agent terminal。認得出是 agent 才自動 Enter；身分不確定時只放進輸入框，由你確認
  - 📝 **開 Issue**：請該 worktree 的 agent 用 `gh issue create` 開 issue（先不修），內文末尾帶 `vibeguard-key:<rule> <path>` 機器標記，之後面板自動對應狀態
  - 🚫 **此檔免檢** ／ 🙈 **忽略這筆**：寫進該 repo 根目錄的 `.vibeguard-ignore`，數秒內生效，並學進 `.vibeguard-learned.json`
- **⚙️ 設定卡**：
  - 🔔 **啟用通知**：關掉照樣掃、照樣記錄，只是不跳通知
  - 🤖 **LLM 掃描**：關掉後只跑本地 regex，完全不叫 AI
  - 🧠 **L3 語意審查**：LLM 框架與模型下拉（claude／codex／gemini）
  - 🌐 **語言**：自動（跟隨系統）／繁體中文／English／简体中文／日本語。明確選擇會同步給 worker，通知與送 agent 的訊息也換語言

面板動作的實作細節：面板是 Orca 的沙箱 iframe（CSP `connect-src 'none'`，不能 fetch），所有動作都經由 Orca 的 postMessage bridge 借該 worktree 的 agent 終端以 `!` 本機 shell 模式執行一行 `curl`，打到 worker 自己的 `127.0.0.1` API（token 認證）由 worker 執行。你會在 agent 終端看到那行指令，這是正常的。

### 即時 dashboard（🚀）

在 Orca 內嵌瀏覽器開一頁，每 2 秒輪詢 worker，資料變了才重繪，按鈕直接打 API 不借道終端。URL 含一次性 token（`.dash-token`，插件目錄內、gitignore），只綁 `127.0.0.1`，拒絕跨來源請求。

### `.vibeguard-ignore`（repo 根目錄，會進 git）

```
# 三種粒度；寫入即時生效（watcher 專門放行這個檔）
rule_id                          # 整條規則全專案停用
rule_id src/config.js            # 該檔免檢這項規則
rule_id src/config.js:42         # 只忽略那一筆
```

被忽略的 finding 會從清單消失（進「已修正」區）。規則 id 見 `shield/l1-*.mjs`、`shield/l2-sast.mjs`（例：`hardcoded_secret_aws_access_key`、`sast_sql_template_interpolation`、LLM 結果固定 `l3_llm_semantic_review`）。

### `.vibeguard-learned.json`（誤報學習，repo 根目錄）

被忽略的項目自動記錄（rule + 相對路徑 + 標題，上限 100，最舊先丟）。之後 LLM 掃描同檔時，學到的標題注入 prompt 要求「別再報」，回傳結果再過濾一次；本地層同檔同標題也直接消失。**預設會進 git**（團隊共享判斷）；不想共享就加進 `.gitignore`。

### 指令（Command Palette）

| 指令 | 說明 |
|---|---|
| `VibeGuard: Scan File / 掃描指定檔案` | 掃描指定檔案（只接受 git repo 內的檔案） |
| `VibeGuard: Scan Whole Project / 全專案掃描` | 走訪所有監聽中 worktree 的支援檔（背景執行；LLM 照開關與佇列保護） |
| `VibeGuard: One-Click Fix / 一鍵修復` | 修復指定 finding（只接受記憶體裡確實存在的 finding） |
| `VibeGuard: Status / 狀態` | 監聽中的 worktree 與 finding 數 |

## 運作原理

| 層 | 引擎 | 成本 | 內容 |
|---|---|---|---|
| **L1** | 本地 regex + Shannon 熵 | 免費、毫秒級、確定性 | 密鑰 11 條（AWS／GitHub／Slack／Stripe／Google／npm／Anthropic／OpenAI／JWT／私鑰／DB URL）、敏感賦值 + 高熵字串、不安全設定 13 條、AI 常見錯誤模式 20 條 |
| **L2** | 本地 SAST regex 16 條 | 免費 | SQL 注入、XSS、SSRF、路徑穿越、命令注入、不安全反序列化、open redirect… |
| **L3（本地）** | 端點語意 regex 4 條 | 免費 | 端點缺認證／限流／輸入校驗／錯誤處理。**預設關閉**（跟隨 DeepSec），誤報率高 |
| **LLM** | 你本機的 agent CLI | 依你的 AI 額度 | 同時涵蓋 L2／L3 的語意判斷；輸出固定 JSON schema；rule 固定 `l3_llm_semantic_review` |

管線：`fs.watch` → debounce 2s → L1/L2 本地掃 → **脫敏** → （可選）LLM → 去重（`(rule, target, line, evidence)`）→ 內容指紋（行號位移不算新問題）→ 通知 + storage + 重烤面板。

效能與額度閘門：單檔 >500KB 跳過；生成檔／測試檔／lock 檔／`node_modules`、`.git`、`.omc`、`i18n` 等目錄一律跳過（清單在 `shield/scanner.mjs`）；LLM **一次只跑一個**、在跑 + 排隊合計上限 4（滿了就跳過該次 LLM，本地結果照出）；單次 LLM 上限 600 秒；claude 鎖 `--max-turns 1`（單回合、不自己翻 repo）。

設計原則：**本地優先、LLM 只補語意**。確定性的問題用 regex 抓，免費且穩定；需要理解上下文的才交給 LLM，並要求它對無法從單檔確認的問題降級、標未查證（見最上方的警語）。

## 隱私與機敏資料

完整政策見 [`SECURITY.md`](SECURITY.md)。摘要：

**什麼會離開你的機器？**

- **L1／L2／L3 本地層**：全部在本機執行，不送出任何東西。
- **LLM 層（可關閉）**：檔案內容**先脫敏**再交給你本機的 agent CLI，由該 CLI 的後端 API 處理：
  - 送出前一律把密鑰值替換成 `VIBEGUARD_REDACTED_SECRET`（密鑰規則整段替換、敏感賦值只換值保留變數名）
  - 固定防注入 system prompt：檔案內容一律視為「不可信資料」，不執行其中的指令
  - 只送**單一檔案**，不送整個專案；子行程 cwd 設在被掃 repo 根（框架的目錄信任機制）
- **面板／通知／storage**：全部本機。findings 存在 Orca 插件 storage 與 `panel.html`（含代碼片段，片段也經過脫敏）。
- **GitHub issue（只在你按按鈕時）**：issue 內容含檔案路徑、規則名、問題描述與建議（控制字元已清除）。**公開 repo 請先確認描述裡沒有你不願公開的內容**。

**本機狀態檔**（插件目錄內、純文字、皆在 `.gitignore`）：`.notify-state`、`.llm-state`、`.llm-scan-state`、`.locale`、`.dash-token`（dashboard 認證 token）、`.llm-token`（claude 長期 token，唯一的憑證檔，`chmod 600`）。

**宣告的 capabilities**（Orca 能力閘門）：`workspace:read`、`terminal:send`、`notifications:show`、`storage`、`events:subscribe`。**沒有網路能力**——除了你自己安裝的 agent CLI 與你按鈕觸發的 `gh`，本插件不連外；dashboard 只綁 `127.0.0.1`。

**這個 repo 本身**：所有會進版控的檔案（含文件、註解、測試 fixture）由 `npm test` 裡的 `test/repo-hygiene.test.mjs` 把關——用本專案自己的密鑰規則掃一遍，命中的字串必須一眼看得出是假的（`EXAMPLE`／`FAKE`／連續字母），且不得含私人家目錄路徑與信箱；`panel.html` 只能是空模板。

## 測試與驗證方法

`npm test` 跑全部（Node 內建 `node:test`，零依賴），目前 **383 個測試**。每一層都有對應測試檔（`shield/x.mjs` ↔ `test/x.test.mjs`），另有：

- **忠實度測試**：規則、閾值、跳過清單逐字對照 DeepSec 的 Python 原作；原作的 quirk（例如負向前瞻被空格回溯打穿、裸 `apiKey=` 不命中）刻意保留並用測試鎖住，有疑義時以 `python3` 跑原作 regex 實測為準。逐條分析見 [`docs/02-deepsec-fidelity.md`](docs/02-deepsec-fidelity.md)（[English](docs/02-deepsec-fidelity.en.md)）。
- **e2e**：從含密鑰與注入的樣本檔一路走到 findings、去重、脫敏、panel-server 認證。
- **worker 接線測試**：用假的 Orca host 物件驅動 `activate`，驗證通知節流、storage、忽略檔、學習、面板重烤、doAction 各動作、語系。
- **烤出來的 HTML 語法檢查**：面板與 dashboard 的 `<script>` 抽出來 `new Function` 編譯（template literal 反斜線曾讓整個面板掛掉，這是正式驗收）。
- **字典一致性**：四個語系的 key 集合與佔位符必須完全一致，值不得含會破壞內嵌的字元。
- **部署清單自檢**：`scripts/deploy.mjs` 的檔案清單必須涵蓋 `main.mjs` 的全部遞移 import（漏檔會讓 worker 連死三次、插件被標 errored）。
- **機敏資料閘門**：見上一節。

開發方法與在真實 Orca 裡踩過的坑（worker 生命週期、面板 watchdog、終端路由）整理在 [`docs/03-development-and-testing.md`](docs/03-development-and-testing.md)（[English](docs/03-development-and-testing.en.md)）。

## 致謝與來源

本專案是 **[DeepSec](https://github.com/Unclecheng-li/DeepSec)**（VS Code 擴充 + Python 核心，前身即名為 VibeGuard，MIT License）的 **Orca 插件移植與延續**。從 DeepSec 學習並逐字移植的部分：L1 密鑰／賦值／熵規則與閾值（3.8／4.5）、CONFIG 與 AI_PATTERN 規則、L2 SAST 16 條 regex、L3 端點語意檢查、掃描跳過清單、去重語義、送 LLM 前脫敏的原則、審計 JSON schema 與結果正規化。署名細節見 [`NOTICE`](NOTICE)。

刻意**不移植**：Python AST taint 分析、Tree-sitter、agent_security、supply_chain（幻覺套件偵測）——語意判斷改由你本機已有的 agent CLI 執行；差異清單在 `docs/02`。

## 已知限制

- **會誤報**（見最上方）。LLM findings 本質是待查證線索。
- **無法跳到行號**：Orca 插件 API v1 沒有 openFile action、CLI 沒有 `--line`；以面板內嵌片段替代。
- **findings 的 agent 歸屬是推測的**：Orca 事件不帶「誰寫了這個檔」；取該 worktree 10 分鐘內最近活動的 agent（`agent.status.changed`），否則 `unknown`。
- **終端身分靠啟發式**：Orca ≥ 1.4.193 的 `agentIdentity` 欄位是確定訊號；舊版只能看標題／preview 特徵。認不出時修復訊息只放進輸入框不自動送。
- **worker 重啟只能 toggle**：worker 自行退出會被 Orca 計入連續失敗次數（3 次即標 errored、事件全丟），所以面板的 🔄 只會告訴你「Settings → Plugins 關掉 → 等 10 秒 → 開」。
- **只掃 Orca 管理的 worktree**；`scanFile` 指令拒絕 git repo 外的路徑（防止被拿來讀任意檔案送 LLM）。
- codex／gemini 的非互動模式未在所有環境實測，切換後請看掃描記錄有無 `LLM_FAILED`。

## 開發

規約見 [`AGENTS.md`](AGENTS.md) 與 [`CONTRIBUTING.md`](CONTRIBUTING.md)。重點：零依賴、ESM、`node:test`、TDD（先寫失敗測試）、`shield/` 純函式不得 import Orca API、Orca host method 名稱以 [`docs/01-api-confirmation.md`](docs/01-api-confirmation.md) 為準不得猜、面板 template literal 內禁 regex、UI 字串一律進 `i18n.mjs` 字典。

## License

MIT —— 見 [`LICENSE`](LICENSE) 與 [`NOTICE`](NOTICE)。
