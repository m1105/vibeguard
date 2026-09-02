# VibeGuard for Orca

AI 生成代碼即時安全守護 Orca 插件。開發方式與 API 結論見 `docs/01-api-confirmation.md`（所有 host method / event / capability 名稱以該文件為準，禁止猜測）。

## 開發規約（所有貢獻者含 AI agent 必守）

- **零依賴**：不加任何 npm dependency，只用 Node 內建模組（插件 worker 環境無 node_modules）。
- **ESM**：`.mjs` / `"type": "module"`，只用 `import/export`。
- **測試**：Node 內建 `node:test` + `node:assert/strict`；跑 `npm test`（= `node --test`，Node ≥25 不接受目錄參數）。TDD：先寫失敗測試再實作。
- 註解：簡短、只寫「為什麼」，中文或英文皆可，跟隨周圍程式碼。
- 純函式優先：shield/ 下模組不得 import Orca 專屬 API，方便單測；IO（fs/child_process/host.call）以參數注入。
- 檔案結構：`shield/`（掃描引擎，純邏輯）、`main.mjs`（worker 接線）、`panel.html`、`panel-server.mjs`、`test/`、`issues/`（任務規格）、`docs/`。
