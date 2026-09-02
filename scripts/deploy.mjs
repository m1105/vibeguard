// scripts/deploy.mjs — 佈署插件到專用資料夾（安裝/更新一律從那裡裝）。
// 為什麼：直接從開發 repo 安裝會把 .omc/.git 等大目錄算進安裝上限（77MB/2081 檔），
// 每次都得搬開；專用資料夾只放 runtime 檔案，乾淨且可重複執行。
// 用法：node scripts/deploy.mjs
//   首次安裝：Settings → Plugins → + 安裝插件 → 選印出的資料夾
//   之後更新：重跑本 script → 插件卡片 ⋯ → 重新安裝/Update
import { cp, mkdir, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = dirname(dirname(fileURLToPath(import.meta.url)));
const DEST = join(homedir(), 'orca', 'plugins-deploy', 'vibeguard-orca');
const INCLUDE = ['orca-plugin.json', 'package.json', 'main.mjs', 'panel-renderer.mjs', 'panel-server.mjs', 'dashboard.mjs', 'shield', 'seeds'];

// 就地覆寫、不砍目錄：devPluginPaths 指著這裡（方案 C），目錄消失會讓 dev 插件短暫失蹤
await mkdir(DEST, { recursive: true });
for (const name of INCLUDE) await cp(join(SRC, name), join(DEST, name), { recursive: true, force: true });
// panel.html 只在不存在時初始化空模板——覆蓋會抹掉 worker 的活資料並觸發
// 假的「從未活動」警示（worker 的有意義才烤不會為沒變的資料補烤）。
// 新模板生效不靠這裡：toggle 後 worker 首烤（hash 必變）自然帶入。
const { buildPanelHtml } = await import(join(SRC, 'panel-renderer.mjs'));
const panelPath = join(DEST, 'panel.html');
const { access } = await import('node:fs/promises');
const panelExists = await access(panelPath).then(() => true, () => false);
if (!panelExists) await writeFile(panelPath, buildPanelHtml({ generatedAt: null, groups: {}, scans: [] }));
// 冒煙自檢：部署缺檔會讓 worker import 秒死 → supervisor 3 次重啟 → 插件標 errored
// （2026-08-30 實際發生：漏了 dashboard.mjs）——部署完必須驗證 main.mjs 可載入
await import(join(DEST, 'main.mjs'));
console.log('已佈署到：' + DEST + '（main.mjs 載入自檢通過）');
