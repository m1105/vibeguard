# VibeGuard — Orca 插件 API 確認報告（規劃書「第一步」交付）

來源（雙重驗證）：
- 官方 repo 原始碼 + hello-orca 範例：`github.com/stablyai/orca`（本地 sparse clone 於 `.orca-api-ref/orca-repo/`）
- 本機實裝 `/Applications/Orca.app` 的 app.asar 編譯產物（`.orca-api-ref/*.js`）

## 1. host method 確切名稱與簽章（PLUGIN_HOST_API_V0 完整清單，僅此 13 個）

| method | params | result | capability | panel 可呼叫 |
|---|---|---|---|---|
| `workspace.readContext` | `{}` | `{branch, displayName, terminals:[{id}]} \| null`（focused worktree） | `workspace:read` | ✅ |
| `terminal.sendText` | `{terminalId: string(必填), text: string(1..4096), enter?: bool}` | `{accepted: bool}` | `terminal:send` | ✅ |
| `notifications.show` | `{title: string(1..120), body?: string(≤1000)}` | `{delivered: bool}` | `notifications:show` | ✅ |
| `storage.get` | `{key ≤256}` | `{value: json}` | `storage` | ❌ |
| `storage.set` | `{key, value: json}`（value ≤256KB，總量 ≤5MB，≤1024 keys） | `{ok: true}` | `storage` | ❌ |
| `storage.delete` | `{key}` | `{ok: true}` | `storage` | ❌ |
| `storage.keys` | `{}` | `{keys: string[]}` | `storage` | ❌ |
| `secrets.get/set/delete` | `{key[, value ≤64KB]}` | … | `secrets` | ❌ |
| `settings.get/set` | `{}` / `{key, value}` | … | `settings:own` | ❌ |
| `events.subscribe` | `{events: EventName[]}` | `{subscribed: [...]}` | `events:subscribe` | ❌ |

**規劃書猜測對照**：`notifications.show` ✅、`terminal.send` → 實為 **`terminal.sendText`**、`storage` 系列 ✅。
**不存在的 method**：`openFile`（無開檔 API，更無行號參數）、`panel.notifyUpdate`、`workspace.activeFile`。

## 2. 事件清單（閉集合，僅 3 個）

`worktree.created` `{worktreeId, path, branch}`、`worktree.removed` `{worktreeId, path}`、`agent.status.changed` `{worktreeId|null, paneKey, state, receivedAt}`。

**❌ 沒有任何「檔案寫入/變更」事件。** → 採用備援：worker 自己跑 `fs.watch`（見 §5）。

## 3. capability 名稱（閉集合，typo 會直接 manifest 驗證失敗）

`workspace:read` / `terminal:send` / `notifications:show` / `storage` / `secrets` / `events:subscribe` / `settings:own`。
規劃書的五個全對；另外可用 `secrets`、`settings:own`。

## 4. Panel 通訊（與規劃書骨架差異最大處）

- Panel 是 sandboxed iframe（`sandbox="allow-scripts"`，opaque origin）。
- **沒有 `window.orcaPanel` 全域**。panel.html 必須自己實作 postMessage 協定（照 hello-orca/panel.html）：
  - 送：`window.parent.postMessage({type:'orca-panel-action', requestId, action, params}, '*')`
  - 收：`window.addEventListener('message')` 過濾 `data.type==='orca-panel-action-result'`，欄位 `{requestId, ok, value | error, errorCode}`
- **panel 只能呼叫 3 個 action**：`workspace.readContext`、`terminal.sendText`、`notifications.show`。**不能讀 storage。**
- 限制：單則訊息 ≤64KB、30 則/10s 速率上限、watchdog ping/pong（10s/5s）。
- Host 會注入 Orca design tokens 為 CSS 變數：`--foreground` `--background` `--border` `--secondary` `--muted-foreground`（panel 樣式應使用它們而非寫死顏色）。
- **沒有 worker→panel 的 push 通道**（worker 協定只有 ready/commandResult/eventAck/hostCall/log/fatal）。

→ **Dashboard 資料流改為：worker 在 127.0.0.1 開 HTTP server，panel 用 fetch 輪詢**。panel 的「開檔」「一鍵修復」也走此 HTTP 通道送給 worker 執行。

## 5. Worker 執行環境（關鍵發現）

- Worker 是 **plain Node child process**（fork + IPC，無 Electron、無 sandbox），`main.mjs` 以 dynamic import 載入。
- **能力閘門只管 `host.call`**；worker 本身有完整的 `fs` / `child_process` / `net` 權限。
  - 檔案監聽：worker 直接 `fs.watch` worktree 目錄（路徑來自 `worktree.created` 事件 payload 的 `path`）。
  - L2/L3：worker 直接 spawn `claude -p`（本機已裝 claude CLI），不需走 terminal 來回。
  - 開檔：worker spawn `orca file open <path> --worktree <id>`（CLI 已確認存在；**無 --line 旗標**，跳行 v0 做不到 → 降級為開檔 + 通知帶行號）。
- `activate(orca)`：**default export**；`deactivate` 為可選 named export。`orca` 物件 = `{commands.register(id, handler), events.on(name, handler), host.call(method, params), grantedCapabilities, log(msg)}`。
- ⚠️ **閒置 5 分鐘會被 reap**（`PLUGIN_WORKER_IDLE_REAP_MS`）→ 需要 keepalive（定期 host.call）。
- `terminal.sendText` 的 `text` **上限 4096 字元** → 一鍵修復訊息必須精簡。

## 6. Manifest 校正（相對規劃書骨架）

- **必補 `publisher` 欄位**（kebab-case；安裝身份 = `<publisher>.<id>`）。
- `id` 必須 kebab-case（`vibeguard-orca` ✅）；command id 允許 `vibeguard.scanActive` 形式。
- `contributes.commands` 的 `action` 欄位只限 14 個內建 alias（無開檔類）；自訂命令靠 worker `commands.register`。
- `contributes.events` 只能列 §2 的三個事件（且實際訂閱靠 `events.subscribe` 或 events.on？worker 用 `orca.events.on` 即可，manifest 列出是宣告用途）。
- panels：`{id, title, icon(Lucide 名), entry}`。

## 7. 開發/安裝方式

- **Dev 模式**：Orca settings 的 `devPluginPaths`（陣列）加入本專案目錄 → `PluginDevWatcher` 熱重載。dev path 與已裝插件同 identity 時 dev 優先。
- 正式安裝目錄：`~/Library/Application Support/Orca/plugins/<publisher>.<id>/` + `plugins.lock.json`（source kinds: bundled/git/marketplace）。

## 8. 對規劃書的強制設計變更（無替代方案）

| 規劃書假設 | 現實 | 決策 |
|---|---|---|
| 檔案寫入事件 | 不存在 | worker `fs.watch` 遞迴監聽 worktree |
| `panel.notifyUpdate` push | 不存在 | worker 開 localhost HTTP，panel 輪詢 |
| host 開檔帶行號 | 無此 API | spawn `orca file open`；行號只進通知/面板文字 |
| L2/L3 走 terminal 來回 | 不可靠 | worker spawn `claude -p` 收 JSON |
| `window.orcaPanel` | 不存在 | panel 自實作 postMessage（照 hello-orca） |

## 9. Worker 啟動模型（實測確認 2026-08-29）

- Worker 是 **lazy 啟動**：`plugin-worker-controller.reconcile()` 只停不啟；啟動點只有兩個——`invokeCommand`（UI 跑插件指令）與 `deliverPluginEvent`（manifest `contributes.events` 訂閱的事件觸發時 `ensure()` 拉起 worker 再投遞）。
- 推論：插件裝好/啟用後，worker 不會自動跑；第一個 `worktree.created` 或手動指令才會啟動。啟動後靠 keepalive（4 分鐘）防 idle reap 常駐。
- 插件卡片的「...」有 worker log 檢視（最近 200 行）；worker 從未啟動時顯示「未記錄日誌行」。
- 安裝有大小/檔案數上限（實測 77MB/2081 檔被擋）；開發用 devPluginPaths 是就地載入不複製。

## 10. Panel 資料通道更正（實測 2026-08-29，推翻 §4 末段的 HTTP 輪詢設計）

- **panel shell 的 CSP 是 `default-src 'none'; connect-src 'none'; script-src 'unsafe-inline'`**（plugin-panel-shell.ts `PLUGIN_PANEL_CSP`）→ sandboxed iframe **完全不能 fetch**，127.0.0.1 HTTP 對 panel 無效（面板永遠顯示「未連線」）。
- panel 能對外的只有 postMessage bridge 的 3 個 action（`workspace.readContext` / `terminal.sendText` / `notifications.show`），沒有任何「讀 plugin 資料」的通道。
- **最終設計（產生式 panel）**：worker 每次掃描後把 findings 內嵌（`window.__VIBEGUARD_DATA__`，`<` 轉義防 `</script>` 逃逸）原子重寫 `panel.html`；panel 每次開啟都從磁碟重讀（plugin-panel-controller.load）。一鍵修復由 panel 自己走 bridge：`readContext` 取 terminals[0].id → `terminal.sendText` 送修復訊息。
- 副產品：dev 模式下 panel.html 重寫會觸發 PluginDevWatcher → plugin refresh（worker spec 不變所以 worker 存活）→ panel 重新掛載拿到新資料。
- panel-server.mjs 保留（worker 側 HTTP 仍可用於 CLI/除錯），但 panel.html 不再依賴它。
- 點列開檔：pluginApi v0 無 openFile action 且 CLI 無 --line，**面板內開檔跳行做不到**，暫從 UI 規格降級（finding 列顯示完整 `path:line` 供手動跳）。
- 既有 worktree 補救已實作（main.mjs）：worker 啟動時 spawn `orca worktree list --json`（候選路徑 orca / /usr/local/bin/orca / /opt/homebrew/bin/orca，GUI fork 的 PATH 很薄）把全部既有 worktree 納入監聽。

## 11. Worker 生命週期補充（實測 2026-08-29）

- Supervisor 對 crash 的重啟上限是 **maxRestarts=3**（backoff 0.5s/2s/5s），超過標 `errored`，host 不再啟動，**只有 toggle 插件開關能重置**；supervisor 狀態在記憶體（`PluginSupervisor.entries`），**完全結束 Orca 再開也會清掉**。
- 開發時**不要 kill worker 進程**來換代碼（會被計為 crash）；正確做法是 toggle 開關（或裝在 devPluginPaths 下改 manifest 類的 spec 欄位）。
- `scripts/dev-worker.mjs` 可本地跑 worker（host.call 全部 stub，storage 寫 /tmp），除錯 worker 行為不必動 Orca。
- **警告：dev-worker 用完務必 Ctrl+C**。殭屍 dev-worker 會繼續監聽所有 worktree 並用它啟動時的舊碼重寫專案 panel.html，跟真 worker 互蓋，面板看起來像「改了沒效」（2026-08-29 實際踩過：16:47 的殭屍把 17:49 新模板蓋回舊模板）。
- 插件的 crash 原因（fatal stack）只進 Orca 記憶體裡的 PluginLogBuffer（200 行 ring），沒有 IPC/CLI 出口；要除錯就用 dev-worker 本地重現（它的 uncaughtException handler 會印 stack）。
- local-path 插件的 worker **直接從源目錄載入**（`~/Library/Application Support/Orca/plugins/<key>/<hash>/` 只是安裝快照，不是執行目錄）；writePanel 用 `import.meta.url` 推回源目錄寫 panel.html。改碼不用重裝，重啟 worker（toggle / app 重開）即可。

## 12. GUI 薄 PATH 環境的兩個坑（2026-08-29 修）

- **spawn 候選競態**：`spawn('orca')` ENOENT 後 Node 仍會對失敗的 child 補發 `close(code -2)`。舊 runCmd 的 close handler 會搶在候選 2 完成前 reject，導致 GUI 環境下所有 CLI 呼叫（worktree list / terminal list / gh）一律失敗（靜默降級）。修法：`failed` flag 擋掉殘留 close（main.mjs runCmd、l23-llm.mjs defaultRunner 同案）。
- **claude 也要候選路徑**：defaultRunner 原本只 spawn bare `claude`，薄 PATH 下 ENOENT → 所有 L2/L3 LLM 掃描靜默失敗（轉 LLM_FAILED）。改為候選清單 `claude` / `/usr/local/bin/claude` / `/opt/homebrew/bin/claude`。

## 13. crash.log 自我 DoS（實測 2026-08-30）

- crash.log 本來寫在**插件目錄**——dev watcher 盯著目錄，`activate start` 一落盤就觸發 refresh，
  activation 進行中 refresh 的 `isCurrentApproved` 參照比對失敗 → worker 在完成當下被 deactivate。
  反覆發生會撞上 §11 的 maxRestarts=3 → 插件標 `errored` 永久不啟動（只有 toggle 能救）。
- **修法：crash log 移到 `os.tmpdir()/vibeguard-crash.log`**（main.mjs `CRASH_LOG_PATH`）。
  插件目錄內任何「activation 期間的寫檔」都有同樣風險，都要避免。
- panel 加了 worker 心跳警示：`DATA.generatedAt`（最後重烤時間）超過 5 分鐘 → 紅色橫條
  「worker 疑似停止」+ 🔄 重新啟用按鈕（借 shell `touch <插件目錄>/main.mjs` 觸發 dev watcher 重載）。

## 14. dev watcher 的完整機制與 Marketplace 逃生門（2026-08-30，從 Orca.app asar 挖源碼確認）

- **PluginDevWatcher**：訂閱每個 devPath，**任何檔案事件**（無 ignore 清單）→ 300ms debounce → `refresh()`。
- **activation 窗口致命**：`ensure()` 在 spawn worker 後做 `isCurrentApproved(plugin)` **物件參照比對**——refresh 重新掃目錄會建新的 plugin 物件，參照不同 → 「changed or was disabled during activation」→ worker 在完成當下被 deactivate。**refresh 對已在跑的 worker 無害**（spawn spec 沒變就 skip），只有 activation 進行中會被殺。
- **Supervisor**：maxRestarts=3、backoff 500/2000/5000ms；clean exit（code 0）不算 crash 不計 restart。activation 被殺不會自動重試——refresh 不會主動 ensure，插件就停在 dead 直到下一次 toggle。
- **插件目錄永遠不會真的安靜**：Orca 自己對 repo 跑 git ops（.git lock 檔，實測 .git dir mtime 每分鐘級變動）、agent 工具寫 `.omc/`/`.serena/`、我們自己烤 panel.html。§13 的 crash.log 只是第一個被抓到的寫入源。**結論：devPluginPaths 模式先天脆弱，只能開發用。**
- **正式安裝走 Marketplace**：repo 根放 `orca-marketplace.json`（schema：`{name, owner, plugins:[{id: "<publisher>.<id>", source:{kind:"git",url,ref}, description?, categories?}]}`，strictObject，類別需小寫 slug；保留 ID `stablyai.orca-*` 不可佔用）。Settings → Plugins → Marketplaces 加 git source → 瀏覽 → Install。git 安裝的執行目錄是 `plugins-data` 下的內容雜湊快照，**沒有 watcher**。更新 = git push 後在 Marketplace UI 按 Update。
- **dev 模式 toggle 協議**：按一次、等 10 秒；連點會讓多次 activation 互殺（實測 90ms 內 14 次 activate/deactivate 循環）。
- CLI 無 `orca plugin` 子指令（2026-08-30 確認），安裝/啟停只能走設定 UI。

## 15. `terminal list` 的 `agentIdentity` 欄位（實測 2026-09-02，Orca 1.4.193）

`orca terminal list --json` 的每個 terminal 物件在 1.4.193 多了 `agentIdentity`（實測值：`"claude"`、`"kimi"`；純 shell 終端沒有這個欄位）。這是**確定訊號**，比 §11 之前只能看 `title`／`preview` 的 TUI 特徵可靠得多。`main.mjs` 的 `isAgentTerminal` 現在先看它、沒有才退回啟發式（舊版 Orca 相容）。其餘欄位（`handle`、`worktreeId`、`worktreePath`、`title`、`preview`、`connected`、`writable`）不變。
