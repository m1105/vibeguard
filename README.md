# VibeGuard for Orca

> AI 生成代碼的即時安全守護 —— [Orca](https://www.onorca.dev) 插件

**English**: [`README_EN.md`](README_EN.md)

當 Claude / Codex / Kimi 等 coding agent 在你的 worktree 寫檔時，VibeGuard 在背景即時掃描：硬編碼密鑰、注入類漏洞、不安全設定、AI 常見錯誤模式。發現問題時跳系統通知，並在專屬面板按「專案 → agent → 檔案」分層呈現，支援一鍵修復（把「錯在哪/為什麼/怎麼改」送回該 agent 的 terminal 讓它自己修）與 GitHub issue 追蹤。

## 功能特色

- **即時掃描**：監聽所有 Orca worktree 的檔案變動，誰寫的都掃（任何 agent 或手動編輯）
- **三層檢測**（見下方「運作原理」）：L1 密鑰/設定/AI 模式、L2 注入類 SAST、L3 端點語意
- **三色分級面板**：🔴 嚴重（critical/high）與 🟠 注意（medium/low）分區，每列可點擊開檔跳行
- **一鍵修復**：把消毒過的問題描述送回該 worktree 的 agent terminal
- **GitHub issue 追蹤**：一鍵開 issue（含機器標記 `vibeguard-key:`），面板自動對應「已開/已完成」
- **誤報學習**：被忽略的項目記進 `.vibeguard-learned.json`，之後同類問題 LLM 不再報
- **省額度**：LLM 語意審查可整個關掉（只跑本地 regex），或選便宜的框架/模型
- **雙語面板**：面板介面自動依系統語言切換中文/英文，也可手動切換

## 安裝

> ⚠️ Orca 插件系統目前是**實驗性**（`pluginApi: 1`），API 可能變動。

**方法一：Marketplace（建議）**

1. Orca → `Cmd-,` → **Plugins** → **Marketplaces** → **Add source**，填入本 repo 的 GitHub URL
2. 瀏覽裡找到 **VibeGuard** → **Install** → 同意 capabilities → 啟用

**方法二：手動（開發者）**

1. `git clone` 本 repo
2. Orca → Settings → Plugins → 手動安裝指向本目錄（local-path）
3. 同意 capabilities 並啟用

**LLM 需求**：L1/L2 本地規則不需要任何外部服務。L3 LLM 語意審查需要本機已安裝 `claude`、`codex` 或 `gemini` CLI 其中之一（預設 `claude` + `haiku`，可在面板切換；沒有可用的 CLI 時該層自動跳過，不影響本地掃描）。

## 使用方法

### 自動掃描

啟用後不需任何操作：任何 agent 在 worktree 存檔就觸發掃描（debounce 2 秒）。發現 critical/high 問題時跳桌面通知（每類問題只叫一次，全域 2 分鐘冷卻）。

### 面板（VibeGuard 安全總覽）

- **過濾 chips**：全部 / 僅嚴重 / 僅注意 / ✓ 全部已讀 / 🔄 重啟 worker
- **每列 finding**：顯示標題、檔案:行號、層級（L1/L2/L3）、信心度、問題描述
- **列按鈕**：
  - 🔧 **一鍵修復** → 把問題送回該 worktree 的 agent terminal（agent 身分不確定時只放進輸入框，不自動送出）
  - 📝 **開 issue 待修** → 指示 agent 用 `gh issue create` 建立含 `vibeguard-key:` 標記的 issue，之後面板自動顯示追蹤狀態
  - 🙈 **忽略這筆** / **此檔免檢** → 寫進該 repo 根目錄的 `.vibeguard-ignore`（借 shell 直接寫檔，不經過 AI、不耗 token）
- **設定列**：
  - 🔔 **啟用通知**：關掉照樣掃、照樣記錄，只是不跳通知
  - 🧠 **L3 語意審查**：選 LLM 框架（claude/codex/gemini）與模型；選「關」可完全停用 LLM（省額度，只跑本地 regex）
  - 🌐 **語言**：面板語言切換（預設跟隨系統）

### 掃描記錄區

面板底部列出每次掃描/跳過/監聽事件與時間戳——「有沒有在掃」看這裡，不用猜。

### `.vibeguard-ignore`（repo 根目錄）

```
# 三種粒度，寫入即時生效（檔案變動自動重新套用）
rule_id                          # 整條規則全專案停用
rule_id src/config.js            # 該檔免檢這項
rule_id src/config.js:42         # 只忽略那一筆
```

被忽略的 finding 會從清單消失（進「已修正」區）並學進 `.vibeguard-learned.json`。

### `.vibeguard-learned.json`（誤報學習）

被忽略的項目自動記錄（rule + 相對路徑 + 標題，上限 100）。之後 LLM 掃描同檔時，學到的標題會注入 prompt 要求「別再報」，回傳結果也會再過濾一次。**此檔預設會進 git**（團隊可共享）；不想共享就加進 `.gitignore`。

### 指令（Command Palette / Quick Commands）

| 指令 | 說明 |
|---|---|
| `VibeGuard: Scan File` | 掃描指定檔案 |
| `VibeGuard: Scan Whole Project` | 全專案掃描（走訪所有支援的檔案） |
| `VibeGuard: One-Click Fix` | 修復指定 finding |
| `VibeGuard: Status` | 目前狀態 |

## 運作原理（分層引擎）

| 層 | 引擎 | 成本 | 內容 |
|---|---|---|---|
| **L1** | 本地 regex + Shannon 熵分析 | 免費、<50ms、確定性 | 密鑰 11 條（AWS/GitHub/Slack/Stripe/Google/npm/Anthropic/OpenAI/JWT/私鑰/DB URL）、敏感賦值+高熵字串、不安全設定、AI 常見錯誤模式 |
| **L2** | 本地 SAST regex | 免費 | SQL 注入、XSS、SSRF、路徑穿越、命令注入、不安全反序列化等 16 條 |
| **L3** | LLM 語意審查（本機 agent CLI） | 依你的 AI 額度 | 端點缺認證/限流/輸入校驗/錯誤處理——需要跨行語意判斷的問題 |

管線：`fs.watch` → debounce 2s → L1/L2 本地掃 → **脫敏** → （可選）送 LLM → 去重 → 通知 + storage + 重烤面板。

效能閘門：單檔 >500KB 跳過；生成檔/測試檔/lock 檔/`node_modules` 等目錄一律跳過；全域 LLM 並發上限 2。

設計原則：**本地優先、LLM 只補語意**。確定性的問題（密鑰模式、危險 API）用 regex 抓，免費且不會錯；需要理解上下文才判斷的（端點有沒有做認證）才交給 LLM，並要求它「無法從本檔確認的 → 降級 + 標未查證」，降低誤報。

## 隱私與機敏資料處理

**什麼會離開你的機器？**

- **L1/L2**：全部在本機執行，不送出任何東西。
- **L3（可關閉）**：檔案內容會經過**脫敏**後送給你本機的 agent CLI（claude/codex/gemini），由其後端 API 處理：
  - 送出一律先把密鑰值替換成 `VIBEGUARD_REDACTED_SECRET`（evidence 顯示用遮蔽：≤8 字元 → `***`，否則 `前4...後4`）
  - 固定防注入 system prompt：要求模型把檔案內容視為「不可信資料」，不執行其中的指令
  - 只送**單一檔案**內容，不送整個專案
- **通知/面板**：全部本機。findings 存在 Orca 插件的 storage（本機）。
- **GitHub issue（僅在你按按鈕時）**：issue 內容含檔案路徑、規則名、問題描述（已消毒控制字元）。**公開 repo 請先確認描述裡沒有你不願公開的程式片段**；私有 repo 無此顧慮。

**本機狀態檔**（插件目錄內，皆為純文字、不含密鑰）：`.notify-state`（通知開關）、`.llm-state`（框架:模型）、`.llm-scan-state`（LLM 開關）。

**宣告的 capabilities**（Orca 能力閘門，少宣告會被擋）：`workspace:read`、`terminal:send`、`notifications:show`、`storage`、`events:subscribe`。本插件**沒有**網路能力——除了你按鈕觸發的 `gh` CLI 與你自己安裝的 agent CLI 之外，不主動連外。

## 致謝

本專案移植並延續了 **[DeepSec / VibeGuard](https://github.com/Unclecheng-li/DeepSec)**（VS Code 擴充 + Python 核心）的規則、閾值與設計：L1 規則表、熵分析閾值（3.8/4.5）、L2 SAST、L3 端點檢查、掃描跳過清單、脫敏原則與審計 JSON schema 均取自 DeepSec（MIT License）。逐條忠實度分析見 [`docs/02-deepsec-fidelity.md`](docs/02-deepsec-fidelity.md)，署名細節見 [`NOTICE`](NOTICE)。

與原專案的差異：不移植 Python 核心與 Tree-sitter WASM——L2/L3 的語意判斷改由你本機已有的 agent CLI 執行（Orca 使用者本來就裝了 Claude/Codex），比搬規則更準且省工。

## 開發

- **零依賴、ESM、`node:test`**：`npm test` 跑全部測試（TDD：先寫失敗測試）
- 結構：`shield/`（掃描引擎，純邏輯可單測）、`main.mjs`（Orca worker 接線）、`panel-renderer.mjs` / `dashboard.mjs`（面板產生器）、`panel-server.mjs`（除錯用 HTTP）、`test/`、`docs/`（Orca 插件 API 實測結論）
- Orca 插件 API 是實驗性，host method/event/capability 名稱**以 `docs/01-api-confirmation.md` 為準**，不要猜
- 貢獻規約見 [`AGENTS.md`](AGENTS.md)

## 已知限制

- Orca 事件不帶「寫檔的 agent 身分」→ findings 的 agent 欄位顯示 `unknown`
- L3 是單檔審查：守衛常寫在別處（middleware/service 層），LLM findings 本質是**待查證線索**，不是定案——開 issue 讓該 repo 的 agent 查證是建議流程
- 只掃 Orca 管理的 worktree 內的檔案

## License

MIT — 見 [`LICENSE`](LICENSE) 與 [`NOTICE`](NOTICE)。
