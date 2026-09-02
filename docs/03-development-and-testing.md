# 03 — 開發方法、測試方法與在真實 Orca 裡踩過的坑

_English: [`03-development-and-testing.en.md`](03-development-and-testing.en.md)_

這份文件回答三個問題：這個插件是**怎麼做出來的**、**怎麼驗證它真的能用**、以及接手的人（包含 AI agent）**最容易在哪裡跌倒**。API 名稱的唯一真相在 [`01-api-confirmation.md`](01-api-confirmation.md)，規則的唯一真相在 [`02-deepsec-fidelity.md`](02-deepsec-fidelity.md)，這裡不重複。

## 1. 做法：從 DeepSec 移植到 Orca 插件

### 1.1 為什麼是移植而不是重寫

[DeepSec](https://github.com/Unclecheng-li/DeepSec) 已經有一套經過整理的規則庫（密鑰格式、熵閾值、注入模式、端點語意）與掃描編排（跳過清單、去重、脫敏）。這些是「知識」，不是「程式碼風格」——重寫等於重新犯一遍原作者已經修過的錯。所以：

- **規則層逐字移植**：每條 regex、severity、閾值、rule id 都對照 Python 原檔（`rules/patterns.py`、`rules/sast.py`、`rules/ai_audit.py`、`scanner.py`）。
- **quirk 也移植**：例如 DOMPurify 的負向前瞻會被空格回溯打穿、賦值 regex 關鍵字前要有 ≥1 個字元（裸 `apiKey=` 不命中）、環境變數引用是判斷「整行」。這些看起來像 bug，但改掉就會跟原作行為分歧、無法互相比對驗證。我們把它們寫成測試鎖住，並在測試裡標 `fidelity quirk`。
- **刻意不移植的部分寫清楚**：Python AST taint、Tree-sitter、agent_security、supply_chain（見 docs/02 #15）。語意判斷改交給使用者本機已裝的 agent CLI，比把整套 AST 搬到 JS 更準、更省工，也符合 Orca 使用者的環境（他們本來就裝了 Claude／Codex）。

### 1.2 分層與純函式

```
shield/            純函式引擎：不 import Orca；IO 全由參數注入
  l1-secrets.mjs   密鑰 11 條
  l1-entropy.mjs   敏感賦值 + Shannon 熵
  l1-rules.mjs     CONFIG 13 + AI_PATTERN 20
  l2-sast.mjs      注入類 16 條
  l3-local.mjs     端點語意 4 條（預設關）
  l23-llm.mjs      脫敏 → prompt → spawn CLI → 解析 JSON → 正規化
  redaction.mjs    送 LLM 前脫敏
  scanner.mjs      單檔編排、跳過清單、去重
  finding.mjs      Finding 建構、去重、內容指紋（identity）
  learning.mjs     誤報學習（.vibeguard-learned.json）
  watcher.mjs      fs.watch + debounce + 併發閘門
  host-methods.mjs Orca host method 名稱常數（唯一可以改名的地方）
main.mjs           worker 接線：事件、指令、通知節流、storage、面板重烤、doAction API
panel-renderer.mjs 面板（產生式 HTML，資料內嵌）
dashboard.mjs      即時 dashboard 頁（panel-server 供應）
panel-server.mjs   127.0.0.1 HTTP（token 認證）
i18n.mjs           UI 字典（四語系）
```

「純函式」不是風格偏好，是**測試策略**：`shield/` 完全不需要 Orca 就能單測，`main.mjs` 則用一個假的 `orca` 物件（記錄所有 `host.call`）與注入的 fs／spawn／CLI 驅動。這讓 383 個測試在 1.5 秒內跑完、不需要任何外部服務。

### 1.3 面板為什麼長這樣（被實測推翻的設計）

原規劃是面板向本機 HTTP server 輪詢。實測 Orca 的 panel shell 對 iframe 設了 CSP `connect-src 'none'`——**面板不能 fetch 任何東西**。因此改成「產生式」：worker 每次掃描後把 findings 內嵌進 `panel.html` 原子重寫，面板每次開啟從磁碟重讀；面板的動作只能走 Orca 的 postMessage bridge（`readContext`／`sendText`／`notify` 三個合法 action），所以按鈕都是「借該 worktree 的 agent 終端以 `!` 模式執行一行 curl 打 worker 的 API」。這條路很繞，但它是唯一在沙箱裡行得通的路，而且 API 端有 token 與 finding 存在性驗證把關。

真即時的需求由 🚀 dashboard 補：Orca 內嵌瀏覽器沒有那個 CSP，可以直接輪詢。

## 2. 測試方法

### 2.1 分層對應

每個 `shield/x.mjs` 有一個 `test/x.test.mjs`；規則測試的寫法是「一條規則至少一個命中案例 + 一個不命中案例 + 邊界案例」。閾值類（熵 3.8／4.5、長度 16–180）都有「剛好在閾值上」的案例。

### 2.2 忠實度驗證

規則 regex 有疑義時，**不猜**：用 `python3 -c` 直接跑 DeepSec 原檔的 regex，比對 JS 版的結果；差異若源自 JS 與 Python regex 引擎的語意差（例如 `\w` 對 Unicode、lookbehind），在測試註解記錄實測結果。跳過清單、rule id、severity 逐字對照 docs/02。

### 2.3 worker 接線測試（`test/main.test.mjs`）

用 `fakeOrca()` 提供 `commands.register`／`events.on`／`host.call`，`fakeDeps()` 注入 readFile／writeFile／spawn 替身／CLI 替身／時鐘。覆蓋：通知只叫未通知過的 critical/high 且 2 分鐘冷卻；忽略檔三種粒度；學習檔寫入與後過濾；面板只在「有意義變化」時重烤與 5 秒節流；刪檔自動進已修正；LLM 開關與佇列滿載跳過；doAction 每種動作與防偽（只認記憶體裡存在的 finding）；語系（通知／訊息／noteKey）；終端分流（agentIdentity 與啟發式）。

### 2.4 端到端（`test/e2e.test.mjs`）

一個同時含 Anthropic key、SQL 模板插值等問題的樣本檔，走完 scanText → 去重 → 每筆欄位齊全 → 脫敏後不含真值 → panel-server 無 token 一律 403。

### 2.5 產物驗收

- **烤出的 HTML 語法檢查**：抽出 `<script>` 用 `new Function` 編譯。這是正式驗收，因為 template literal 裡的反斜線曾把 `/\/[^/]*$/` 烤成 `//` 註解，整個面板 JS 掛掉、所有按鈕沒反應。
- **模板內函式抽出單測**：`sq()`（shell 跳脫）、`clean()`（消毒）、`scanBadge()` 用 regex 從 HTML 抽出來 `eval`／`new Function` 直接測。
- **字典一致性**（`test/i18n.test.mjs`）：四語系 key 集合與佔位符一致；值不含會破壞內嵌的字元。
- **部署清單自檢**（`test/deploy.test.mjs`）：`scripts/deploy.mjs` 的 INCLUDE 必須涵蓋 `main.mjs` 的遞移 import。
- **機敏資料閘門**（`test/repo-hygiene.test.mjs`）：見 SECURITY.md。

### 2.6 手動驗收（真實 Orca）

程式碼測試不能證明「在 Orca 裡真的會動」。實際在 Orca 裡驗證過的鏈路：存一個含假密鑰的檔 → 2 秒內通知 → 面板出現 → 修復訊息落到正確 worktree 的 agent 終端 → 忽略後幾秒消失並進已修正 → 刪檔自動進已修正。每次動到 `main.mjs` 的事件／終端／面板重烤邏輯，都要重跑這條。

## 3. 在真實 Orca 裡踩過的坑（接手必讀）

以下每一條都是實際發生過、花了時間才找到原因的。CLAUDE.md 有更精簡的版本給 AI agent。

### 3.1 worker 生命週期

- **worker 是 lazy 啟動**：啟用插件不會啟動 worker；第一個 manifest 訂閱的事件（`worktree.created`／`agent.status.changed`）或手動指令才拉起。所以 manifest 訂閱 `agent.status.changed` 不只是為了歸屬 agent，更是「agent 一動就把 worker 叫醒」的自動喚醒機制。
- **閒置 5 分鐘會被 reap**：keepalive 每 4 分鐘打一次 `storage.keys`。
- **既有 worktree 收不到 created 事件**：啟動後延遲用 `orca worktree list --json` 補納入監聽。這段**不能在 activate 裡等**——activation 進行中若 host 做 refresh，worker 會在 activate 完成的瞬間被 deactivate。
- **maxRestarts = 3**：worker 每次自行退出都算一次失敗，累計 3 次插件標 `errored`、所有事件被丟、怎麼叫都叫不醒；只有到設定頁 toggle 才會重置計數。所以：程式碼裡**沒有任何 `process.exit`**，面板的「重啟」只會顯示 toggle 指引；crash log 寫到 `os.tmpdir()`（寫在插件目錄會觸發 dev watcher 把 activation 中的 worker 誤殺）。
- **換碼 = deploy + toggle**：`touch` 部署資料夾只會重掛面板，不會換碼。deploy 寫檔時絕不 toggle。

### 3.2 面板

- **panel watchdog**：Orca shell 定期送 `orca-panel-ping`，面板 5 秒內不回 `orca-panel-pong`（帶原 pingId）就被判無響應暫停——「插件面板停止响应」黑畫面的元兇。
- **srcdoc iframe 禁止任何後續導航**：頁內 `location.reload()`、meta refresh 全部無效，而且會把 frame 打進壞狀態導致 pong 停止。更新的唯一路徑是 worker 重寫 `panel.html` → dev watcher → Orca 重新掛載。
- **重烤節流與「有意義變化」**：agent 高頻寫檔時每掃一次就重烤會讓面板閃爍、撞上 watchdog。所以只有 findings／已修正／issues／設定變了才烤，且 5 秒內合併；純掃描記錄變動不烤（另有 10 分鐘 liveness 重烤讓心跳警示能分辨 worker 死活）。
- **檢視狀態存 localStorage**：面板每次重掛都是整份 HTML 重載，捲動位置、已讀、折疊、語言都要自己存。
- **內容指紋**：finding 的身分若含行號，agent 在檔案上方插幾行就會整批「已修正 + 全部 NEW」；改用「rule + target + title + 命中行內容」的指紋，同指紋多筆依行號給序號。

### 3.3 終端路由

- Orca 舊版 API 沒有終端身分欄位（只有 title／preview）；**「認不出 agent 特徵」不等於「是 shell」**——閒置的 agent 沒有 spinner、標題可能是任務名。純指令 + 自動 Enter 誤送 agent 會直接打進對話執行。所以 shell 一律視為不存在，所有指令都走 agent 終端的 `!` 本機 shell 模式（誤中真 shell 只是 event not found，無害）；認不出 agent 時訊息只放輸入框。
- Orca ≥ 1.4.193 的 `terminal list` 帶 `agentIdentity`，是確定訊號；有就直接用。
- `terminal.sendText` 只能送「目前 focus 的 worktree」的終端；跨 worktree 要走 `orca terminal send --terminal <handle>` CLI。修復／開 issue 絕不落回 focused 終端（曾把 A 專案的修法打進 B 專案的 agent）。

### 3.4 LLM 子行程

- GUI fork 的 worker PATH 很薄：CLI 都用候選路徑（`/usr/local/bin`、`/opt/homebrew/bin`），並經 `zsh -lc` 載入使用者環境。
- spawn 候選失敗後 Node 仍會補發 `close(-2)`，要用 `failed` flag 擋掉誤拒。
- `cwd` 必須是被掃 repo 根：claude／codex 的目錄信任機制以 cwd 為準，部署資料夾未受信任會 exit 1。
- 背景 worker 與使用者終端共用 OAuth session 會互搶單次有效的 refresh token（反覆「登入 → 好一下 → 又壞」）。根治：`claude setup-token` 長期 token 存 `.llm-token`，以 `CLAUDE_CODE_OAUTH_TOKEN` 執行。**在 Claude Code session 內裸測 `claude -p` 會被內部憑證通道污染，不能當作 worker 環境的證據**；要驗證請在乾淨環境（unset 全部 `CLAUDE*`／`ANTHROPIC*`）+ token + `zsh -lc` + repo cwd 跑。
- 併發降為 1：兩隻 claude 同時 refresh 會撞壞 session。佇列「在跑 + 排隊」上限 4，滿了就跳過該次 LLM。
- 不自動 fallback 到別的框架：會擅自燒使用者別家的額度；失敗把真因（輸出尾段）寫進掃描記錄。
- claude 鎖 `--max-turns 1`：`claude -p` 是 agentic loop，會自己拿工具翻 repo 查證跑上幾分鐘；我們的設計是單檔審查。

### 3.5 誤報與 dogfooding

- LLM 只看單檔，會把「守衛寫在別處」報成漏洞。prompt 明確要求「跨檔案才能確認的 → severity ≤ medium、confidence ≤ 0.5、描述標『未查證』」，並注入該檔已學到的誤報標題。
- VibeGuard 掃自己時抓到過三個真問題（修復訊息未清洗就自動 Enter 落進 shell 逐行執行；`scanFile` 接受任意路徑可讀任意檔外送 LLM；未消毒的 finding 欄位送進終端形成 prompt injection 管道）與一個模板逸出 bug（`\d` 在 template literal 被吃成 `d`，忽略的去行號一直沒生效）。這也是為什麼「掃自己」列為固定驗收。
