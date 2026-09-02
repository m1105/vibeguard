# VibeGuard for Orca — 開發規約（AGENTS.md）

AI 生成代碼即時安全**提醒** Orca 插件（會誤報，見 README 最上方）。開發方式與 API 結論見 `docs/01-api-confirmation.md`（所有 host method / event / capability 名稱以該文件為準，禁止猜測）；規則來源與忠實度見 `docs/02-deepsec-fidelity.md`；做法、測試方法與踩坑見 `docs/03-development-and-testing.md`；規則背後的原因見 `CONTRIBUTING.md`；機敏資料政策見 `SECURITY.md`。

## 所有貢獻者（含 AI agent）必守

- **零依賴**：不加任何 npm dependency，只用 Node 內建模組（插件 worker 環境無 node_modules）。
- **ESM**：`.mjs` / `"type": "module"`，只用 `import/export`。
- **測試**：Node 內建 `node:test` + `node:assert/strict`；跑 `npm test`（= `node --test`，Node ≥25 不接受目錄參數）。TDD：先寫失敗測試再實作。`npm test` 是唯一閘門，包含機敏資料閘門（`test/repo-hygiene.test.mjs`）與部署清單自檢（`test/deploy.test.mjs`）。
- **純函式優先**：`shield/` 下模組不得 import Orca 專屬 API，方便單測；IO（fs/child_process/host.call）以參數注入。
- **忠實移植**：規則 id、regex、severity、閾值逐字照 DeepSec；quirk 保留並用測試鎖住；有疑義用 `python3` 跑原作比對。
- **i18n**：所有使用者看得到的字串（面板、dashboard、通知、掃描記錄 note、送 agent 的訊息）一律進 `i18n.mjs` 字典；各語系 key 與佔位符必須一致（`test/i18n.test.mjs` 會擋）。
- **template literal 紀律**（`panel-renderer.mjs`、`dashboard.mjs` 的 script 區）：禁 regex 字面值、禁反引號與 `${`、換行寫 `'\\n'`、只用 `textContent`、禁 `location.reload()`。
- **機敏資料**：程式碼／註解／文件／測試／commit 訊息都不得含真密鑰、私人路徑、信箱、私人專案名；fixture 必須一眼假（`EXAMPLE`／`FAKE`／連續字母）。
- **worker 不得自行退出**（`process.exit`、未捕捉 throw）；換碼 = `node scripts/deploy.mjs` + 設定頁 toggle。
- 註解：簡短、只寫「為什麼」，中文或英文皆可，跟隨周圍程式碼。
- 檔案結構：`shield/`（掃描引擎，純邏輯）、`main.mjs`（worker 接線）、`panel-renderer.mjs` / `dashboard.mjs`（產生式 UI）、`i18n.mjs`（字典）、`panel-server.mjs`、`panel.html`（產物，只 commit 空模板）、`test/`、`docs/`、`scripts/`。
