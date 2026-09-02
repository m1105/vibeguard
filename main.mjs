// main.mjs — VibeGuard Orca 插件 worker 入口（ISSUE-09）。
// 頂層不得直接跑：一切動作只在 activate(orca) 被呼叫時發生。

import { readFile as fsReadFile, writeFile as fsWriteFile, rename as fsRename, access as fsAccess, appendFile as fsAppendFile, readdir as fsReaddir, mkdir as fsMkdir } from 'node:fs/promises';
import { existsSync, appendFileSync } from 'node:fs';
import { dirname, join, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { HOST } from './shield/host-methods.mjs';
import { WorktreeWatcher, createGate } from './shield/watcher.mjs';
import { scanText, shouldSkipPath } from './shield/scanner.mjs';
import { llmScan, defaultRunner, LLM_FRAMEWORKS } from './shield/l23-llm.mjs';
import { LEARNED_FILENAME, parseLearned, serializeLearned, isLearned, addLearned } from './shield/learning.mjs';
import { redactForLlm } from './shield/redaction.mjs';
import { assignIdentities, identityOf } from './shield/finding.mjs';
import { startPanelServer } from './panel-server.mjs';
import { buildPanelHtml } from './panel-renderer.mjs';
import { buildDashboardHtml } from './dashboard.mjs';
import { t, resolveLocale, detectSystemLocale, LOCALES, DEFAULT_LOCALE } from './i18n.mjs';

const KEEPALIVE_MS = 4 * 60 * 1000; // worker 閒置 5 分鐘會被 reap（docs/01 §5）
const TERMINAL_TEXT_MAX = 4096; // terminal.sendText 上限（docs/01 §1）

let active = null; // { watcher, keepalive, panelServer }（deactivate 是 named export，無參數，只能走模組層狀態）

// worker 在 Orca 裡死掉時 host 只記 exit code，stack 進記憶體 log buffer（無 IPC/CLI 出口）。
// 所以在 activate 裡掛自己的 handlers 落盤。**不能寫在插件目錄**——dev watcher 盯著目錄，
// 'activate start' 一落盤就觸發 refresh，activation 進行中 refresh 會把 worker 誤殺
// （isCurrentApproved 參照比對失敗），等於自我 DoS。寫到 tmpdir 避開。
// host entry 的 dieFatally 註冊在先，會在我們後面執行：先寫檔再上報退出。
// exit code 0 = clean（reap/deactivate），1 = crash。
import { tmpdir, homedir } from 'node:os';
export const CRASH_LOG_PATH = join(tmpdir(), 'vibeguard-crash.log');

// 狀態檔一律放 stateDir（預設 ~/.config/vibeguard），**絕不寫進插件目錄**：
// 安裝版（Marketplace / git URL）的插件目錄是內容雜湊快照，Orca 在 worker 起動與面板載入前
// 會 hashPluginTree 逐檔驗證（dot 檔也算，只跳過 .git），寫任何檔進去 = Orca 重啟後
// 「failed integrity verification」→ worker 起不來、面板載不進（asar 實證）。而且每次升級換目錄。
export const STATE_FILES = ['.notify-state', '.llm-state', '.llm-scan-state', '.locale', '.notify-open-dashboard', '.dash-token', '.llm-token'];

// 安裝模式偵測：安裝版目錄 = <plugins>/<publisher.id>/<64 hex contentHash>/，旁邊有 `current` 指標檔；
// devPluginPaths（開發者部署資料夾）沒有這個結構。安裝版不烤 panel.html（見上）。
export function detectInstallMode(pluginDir, { exists = existsSync } = {}) {
  const dir = String(pluginDir ?? '');
  if (/^[0-9a-f]{64}$/.test(basename(dir)) && exists(join(dirname(dir), 'current'))) return 'installed';
  return 'dev';
}
let crashLoggingInstalled = false;
let crashAppend = () => {};
function installCrashLogging() {
  if (crashLoggingInstalled) return;
  crashLoggingInstalled = true;
  crashAppend = (line) => { try { appendFileSync(CRASH_LOG_PATH, `${line}\n`); } catch { /* 落盤失敗就算了 */ } };
  process.on('uncaughtException', (err) => crashAppend(`[${new Date().toISOString()}] uncaughtException: ${err?.stack ?? err}`));
  process.on('unhandledRejection', (err) => crashAppend(`[${new Date().toISOString()}] unhandledRejection: ${err?.stack ?? err}`));
  process.on('exit', (code) => crashAppend(`[${new Date().toISOString()}] exit code=${code}`));
}

// GUI app fork 的 worker PATH 很薄（/usr/bin:/bin...），CLI 都走候選路徑
const ORCA_CLI_CANDIDATES = ['orca', '/usr/local/bin/orca', '/opt/homebrew/bin/orca'];
const GH_CANDIDATES = ['gh', '/usr/local/bin/gh', '/opt/homebrew/bin/gh'];

// agent TUI 啟發式（分流 agent/shell terminal；修復訊息給 agent、開檔指令給 shell）
// 標題不含 agent 名時（kimi 的標題是任務文字），輔看 preview 的 TUI 特徵（kimi 的月亮 hint 行）
export const AGENT_TITLE_RE = /[◐◑◒◓✳✱⣿⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏🌕🌖🌗🌘🌑🌒🌓🌔⏺]|claude|codex|kimi|gemini|copilot|cursor|esc to interrupt|ctrl\+o/i;

export function isAgentTerminal(term = {}) {
  // Orca ≥1.4.193 的 terminal list 帶 agentIdentity（'claude'/'kimi'/…）：有就是確定訊號；
  // 沒有（舊版或真 shell）才退回標題/preview 的 TUI 特徵啟發式
  if (typeof term.agentIdentity === 'string' && term.agentIdentity.trim()) return true;
  return AGENT_TITLE_RE.test(`${term.title || ''}\n${term.preview || ''}`);
}

// terminal 分流：舊版 Orca API 沒有終端身分欄位（terminal list 只有 title/preview），
// 「認不出 agent 特徵」≠「是 shell」——agent 閒置時沒有 spinner、標題可能是任務名（如「Init」），
// 純指令 + enter:true 誤送 agent 會直接打進對話執行。所以 shell 一律 null：
// 面板所有指令都走 agent 終端的 ! 本機 shell 模式（! 誤中真 shell 只是 event not found，無害）；
// agentSure=false 時面板 enter:false 放輸入框，由使用者確認。
export function classifyTerminals(terms = []) {
  const usable = terms.filter((t) => t.connected && t.writable);
  const agents = usable.filter(isAgentTerminal);
  const agentSure = agents.length > 0;
  const agent = (agents[0] ?? usable[0])?.handle ?? null;
  return { agent, agentSure, shell: null };
}

function runCmd(candidates, args, cwd) {
  const tryCandidate = (index) => new Promise((resolve, reject) => {
    if (index >= candidates.length) return reject(new Error(`${args[0]} CLI not found`));
    const child = spawn(candidates[index], args, cwd ? { cwd } : {});
    let out = '';
    let err = '';
    let failed = false; // spawn 失敗後 Node 仍會補發 close(code -2)，不得讓它誤拒
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', () => { failed = true; tryCandidate(index + 1).then(resolve, reject); }); // ENOENT → 下一個
    child.on('close', (code) => {
      if (failed) return; // 已交給下一個候選，這個 close 是失敗 spawn 的殘留
      if (code === 0) resolve(out);
      else reject(new Error(`${candidates[index]} exited ${code}: ${err.slice(0, 300)}`));
    });
  });
  return tryCandidate(0);
}

export { runCmd };

function runOrcaCli(args) {
  return runCmd(ORCA_CLI_CANDIDATES, args, null);
}

// finding 欄位消毒：內容來自被掃描檔案與 LLM 回傳（不可信），送進終端前
// 清掉換行/ESC/控制字元（防多行注入與 ANSI 逃脫）並限制單欄長度
const cleanField = (s, max = 500) => String(s ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').slice(0, max);

// 送給 agent 的四欄（與 panel-renderer 的 fields() 同格式、同字典 i18n.mjs）
function messageFields(f, locale) {
  return [
    t(locale, 'msgFile', { loc: `${cleanField(f.target, 300)}:${Number.isInteger(f.line) ? f.line : '?'}` }),
    t(locale, 'msgProblem', { title: cleanField(f.title, 200) }),
    t(locale, 'msgWhy', { description: cleanField(f.description) }),
    t(locale, 'msgSuggest', { suggestion: cleanField(f.suggestion) }),
  ].join('\n');
}

export function buildFixMessage(f = {}, locale = DEFAULT_LOCALE) {
  const text = [t(locale, 'fixHeader'), messageFields(f, locale), t(locale, 'fixFooter')].join('\n');
  return text.length > TERMINAL_TEXT_MAX ? text.slice(0, TERMINAL_TEXT_MAX) : text;
}

export function buildIssueMessage(f = {}, locale = DEFAULT_LOCALE) {
  // 機器標記行（issueKeyLine）格式各語系一致：refreshIssues 靠 `vibeguard-key:<rule> <target>` 對 issue
  const text = [
    t(locale, 'issueHeader'),
    messageFields(f, locale),
    t(locale, 'issueBody'),
    t(locale, 'issueKeyLine', { rule: cleanField(f.rule, 100), target: cleanField(f.target, 300) }),
    t(locale, 'issueFooter'),
  ].join('\n');
  return text.length > TERMINAL_TEXT_MAX ? text.slice(0, TERMINAL_TEXT_MAX) : text;
}

export default async function activate(orca, deps = {}) {
  installCrashLogging();
  crashAppend(`[${new Date().toISOString()}] activate start`);
  const readFile = deps.readFile ?? ((p) => fsReadFile(p, 'utf8'));
  const writeFile = deps.writeFile ?? ((p, s) => fsWriteFile(p, s, { encoding: 'utf8', mode: 0o600 })); // 狀態檔含 token，一律 0600
  const appendFile = deps.appendFile ?? ((p, s) => fsAppendFile(p, s, 'utf8'));
  const fileExists = deps.fileExists ?? (async (p) => { try { await fsAccess(p); return true; } catch { return false; } });
  const orcaCli = deps.orcaCli ?? runOrcaCli;
  const gate = createGate(1); // LLM 並發 1：兩隻 claude 同時 refresh OAuth 會撞車把 session 撞壞（單次有效 refresh token）

  // ── 狀態目錄（見檔頭 STATE_FILES 註解：插件目錄不可寫）──
  const pluginDir = dirname(fileURLToPath(import.meta.url));
  const installMode = deps.installMode ?? detectInstallMode(pluginDir);
  const stateDir = deps.stateDir ?? process.env.VIBEGUARD_STATE_DIR ?? join(homedir(), '.config', 'vibeguard');
  await (deps.mkdir ?? ((p) => fsMkdir(p, { recursive: true, mode: 0o700 })))(stateDir).catch(() => {});
  const stateFile = (name) => join(stateDir, name);
  // 一次性搬遷：0.2.0 以前狀態檔寫在插件目錄（開發者部署資料夾）→ 有而 stateDir 沒有的就搬過去
  for (const name of STATE_FILES) {
    if (await fileExists(stateFile(name))) continue;
    const legacy = await readFile(join(pluginDir, name)).catch(() => null);
    if (legacy != null) await writeFile(stateFile(name), legacy).catch(() => {});
  }

  // L3 背景掃描的 LLM 框架/模型（面板下拉切換 → 寫 .llm-state「框架:模型」，每次掃描前讀）
  const llmStateFile = stateFile('.llm-state');
  // 長期 token 檔（可選）：使用者跑 `claude setup-token` 把印出的 token 存進來（chmod 600）。
  // 有它，worker 的 claude 就不再依賴使用者終端的 OAuth session（兩邊 refresh 會互咬）。
  const llmTokenFile = stateFile('.llm-token');
  // dashboard token 持久化：重啟就換 token 會讓已掛載面板/使用者複製的 curl 全部 bad token
  // （實際發生：免檢按了沒效）。首次生成存檔沿用。
  // 位置警告：這段有 await，必須放在 backfill 排程（scheduleDeferred）之前——
  // activate 後段的任何 await 都會讓 backfill 的 `if (!active) return` 在 active 設定前搶跑而靜默跳過。
  const dashTokenFile = stateFile('.dash-token');
  let dashToken = deps.dashboardToken ?? null;
  if (!dashToken) {
    const saved = (await readFile(dashTokenFile).catch(() => null))?.trim();
    dashToken = saved && /^[0-9a-f]{32}$/.test(saved) ? saved : randomBytes(16).toString('hex');
    if (dashToken !== saved) await writeFile(dashTokenFile, dashToken).catch(() => {});
  }
  async function llmSettings() {
    const s = await readFile(llmStateFile).catch(() => null);
    const m = s && s.trim().match(/^(\w[\w-]*)(?::(\S+))?$/);
    const tok = (await readFile(llmTokenFile).catch(() => null))?.trim() || null;
    return { framework: m?.[1] ?? 'claude', model: m?.[2] ?? null, oauthToken: tok };
  }
  // 語言：.locale 檔（'auto' 或 i18n.mjs 的語系 id；面板/dashboard 的語言選單寫入）+ 系統語言。
  // worker 端用在：桌面通知、送給 agent 的修復/開 issue 訊息、掃描記錄與 doAction 回覆的 note。
  // 面板自己有 navigator.language，這裡的 resolvedLocale 只是它的次順位參考。
  const localeStateFile = stateFile('.locale');
  const systemLocale = deps.systemLocale ?? detectSystemLocale();
  let currentLocale = resolveLocale('auto', systemLocale); // 最近一次讀到的解析結果（同步路徑如 logScan 用）
  async function localeSettings() {
    const raw = (await readFile(localeStateFile).catch(() => null))?.trim() || 'auto';
    const locale = LOCALES[raw] ? raw : 'auto';
    currentLocale = resolveLocale(locale, systemLocale);
    return { locale, resolvedLocale: currentLocale };
  }
  await localeSettings();
  // 掃描記錄 / doAction 回覆的 note：帶 key+params 讓面板用自己的語言翻；note 文字給舊面板相容
  const note = (key, params) => ({ noteKey: key, noteParams: params ?? {}, note: t(currentLocale, key, params) });
  const realLlmScan = deps.llmScan ?? (async (input) => {
    const { framework, model, oauthToken } = await llmSettings();
    const runner = deps.defaultRunner ?? defaultRunner;
    // 只跑使用者選定的框架：自動 fallback 會擅自燒使用者其他家的額度（實際發生過
    // codex usage limit），失敗就把原因記清楚（llmError 進掃描記錄），由使用者決定換誰
    {
      try {
        // cwd = 被掃 repo 根：claude/codex 的目錄信任以 cwd 為準（worker 住的部署資料夾未受信任）
        const cwd = findRepoRoot(input?.path) ?? undefined;
        return await llmScan(input, { runner: (p) => runner(p, { framework, model, cwd, oauthToken }) });
      } catch (err) {
        // 認證類失敗且還沒設長期 token：把根治法直接寫進錯誤（會流到面板的 llmError）
        if (!oauthToken && framework === 'claude' && /authenticat|oauth|api key/i.test(String(err?.message ?? ''))) {
          err = new Error(`${err.message}（根治：終端跑 claude setup-token，把 token 存到插件目錄的 .llm-token）`);
        }
        orca.log?.(`LLM 框架 ${framework} 失敗：${err?.message ?? err}`);
        throw err; // 讓 scanner 記 LLM_FAILED + llmError
      }
    }
  });
  // 佇列滿載保護：agent 高頻寫檔時 LLM 佇列會堆積到幾分鐘（單次上限 120s × 深度）。
  // 「在跑 2 + 排隊 2」滿了就跳過本次 LLM——L1/L2 即時結果照出，LLM 靠下一次變動補掃。
  let llmBusy = 0;
  const LLM_MAX_BUSY = 4;
  const gatedLlmScan = (input) => {
    if (llmBusy >= LLM_MAX_BUSY) {
      orca.log?.(`LLM 佇列滿，跳過：${input?.path ?? ''}`);
      return Promise.resolve([]);
    }
    llmBusy += 1;
    return gate(() => realLlmScan(input)).finally(() => { llmBusy -= 1; });
  };

  // 記憶體中的 findings 分組（dashboard 資料來源；storage 是持久化副本）
  // 啟動時從 storage 載回（worker 會被 lazy 啟動/回收，重啟後要有歷史）
  const memory = {}; // {worktreeId: {agent: [finding]}}
  {
    const got = await orca.host.call(HOST.STORAGE_GET, { key: 'findings' }).catch(() => null);
    if (got?.value && typeof got.value === 'object') Object.assign(memory, got.value);
    // 自清：跳過規則改版後（如新增 test-results/i18n 目錄），舊 finding 因路徑被跳過
    // 永遠不會重掃，會永久卡住——載入時用現行 shouldSkipPath 丟掉
    for (const [wt, byAgent] of Object.entries(memory)) {
      for (const [agent, list] of Object.entries(byAgent)) {
        const kept = (Array.isArray(list) ? list : []).filter((f) => !shouldSkipPath(f?.target ?? ''));
        if (kept.length) byAgent[agent] = kept;
        else delete byAgent[agent];
      }
      if (!Object.keys(byAgent).length) delete memory[wt];
    }
  }

  function mergeIntoMemory(worktreeId, agent, findings, scannedPath) {
    const byAgent = memory[worktreeId] ?? {};
    const prev = byAgent[agent] ?? [];
    // 同一筆（rule+target+line）重掃保留首次發現時間——foundAt 不跳動，面板才不會看起來一直變
    const prevFoundAt = new Map(prev.map((f) => [identityOf(f), f.foundAt]));
    for (const f of findings) {
      const old = prevFoundAt.get(identityOf(f));
      if (old) f.foundAt = old;
    }
    const targets = new Set(findings.map((f) => f.target));
    if (scannedPath) targets.add(scannedPath); // 乾淨重掃也要清掉該檔舊 findings
    // agent 歸屬會隨活動變（unknown → 某 agent）：同檔舊 findings 要從「所有」桶清掉
    for (const [otherAgent, list] of Object.entries(byAgent)) {
      const keptOther = (Array.isArray(list) ? list : []).filter((f) => !targets.has(f.target));
      if (keptOther.length) byAgent[otherAgent] = keptOther;
      else delete byAgent[otherAgent];
    }
    byAgent[agent] = [...(byAgent[agent] ?? []), ...findings];
    if (!findings.length && !(byAgent[agent] ?? []).length) delete byAgent[agent];
    if (Object.keys(byAgent).length) memory[worktreeId] = byAgent;
    else delete memory[worktreeId]; // 空桶不留（乾淨掃描不該改變面板資料形狀）
  }

  async function persistFindings(worktreeId, agent, findings, scannedPath) {
    mergeIntoMemory(worktreeId, agent, findings, scannedPath); // 記憶體先更新（panel 立即可見）
    const got = await orca.host.call(HOST.STORAGE_GET, { key: 'findings' }).catch(() => null);
    const all = got?.value ?? {};
    const byAgent = all[worktreeId] ?? {};
    // 同檔重掃：先從「所有」agent 桶移除該檔舊 findings 再併入新的（agent 歸屬會變）
    const targets = new Set(findings.map((f) => f.target));
    if (scannedPath) targets.add(scannedPath);
    for (const [otherAgent, list] of Object.entries(byAgent)) {
      const keptOther = (Array.isArray(list) ? list : []).filter((f) => !targets.has(f.target));
      if (keptOther.length) byAgent[otherAgent] = keptOther;
      else delete byAgent[otherAgent];
    }
    if (findings.length) byAgent[agent] = [...(byAgent[agent] ?? []), ...findings];
    all[worktreeId] = byAgent;
    await orca.host.call(HOST.STORAGE_SET, { key: 'findings', value: all });
  }

  // 掃描記錄（最近 50 筆，新的在前）——讓使用者能驗證「每次修改都有掃」
  // 持久化到 storage：worker 是 lazy 啟動又會被 reap，純記憶體版一 toggle 插件就整段歸零，
  // 使用者剛看到的那筆掃描記錄會憑空消失（實測抱怨「沒回來呀」）。
  const scanLog = [];
  {
    const got = await orca.host.call(HOST.STORAGE_GET, { key: 'scanLog' }).catch(() => null);
    if (Array.isArray(got?.value)) scanLog.push(...got.value.slice(0, 50));
  }
  let scanLogSaving = null; // microtask 合併：啟動時 12 個 worktree 的 watch 記錄只寫一次
  function logScan(entry) {
    scanLog.unshift({ time: new Date().toISOString(), ...entry });
    if (scanLog.length > 50) scanLog.pop();
    if (!scanLogSaving) {
      scanLogSaving = Promise.resolve().then(() => {
        scanLogSaving = null;
        return orca.host.call(HOST.STORAGE_SET, { key: 'scanLog', value: [...scanLog] }).catch(() => {});
      });
    }
  }

  // 已修正清單（重掃後消失的 finding 視為已修正，cap 100；持久化到 storage）
  const resolved = [];
  {
    const got = await orca.host.call(HOST.STORAGE_GET, { key: 'resolvedFindings' }).catch(() => null);
    // 去重：換版前的資料按 rule+target+行號 記錄，同一個問題每被推移一次就多一筆幽靈，
    // 100 筆上限會被洗掉真正修好的紀錄。新→舊掃過去，同身分只留最新那筆。
    if (Array.isArray(got?.value)) {
      const seen = new Set();
      for (const r of got.value) {
        const k = identityOf(r);
        if (seen.has(k)) continue;
        seen.add(k);
        resolved.push(r);
      }
    }
  }
  const resolvedKey = (f) => `${f.rule} ${f.target} ${f.line}`;

  async function markResolved(target, newFindings) {
    // 抓 merge 前 memory 裡該檔的舊 findings
    const prev = [];
    for (const byAgent of Object.values(memory)) {
      for (const list of Object.values(byAgent)) {
        for (const f of list) if (f.target === target) prev.push(f);
      }
    }
    if (!prev.length) return;
    // 用內容身分比對，不用行號：上方插行造成的整體位移不是「修好了」
    const stillThere = new Set(newFindings.map(identityOf));
    const now = new Date().toISOString();
    let changed = false;
    for (const f of prev) {
      if (stillThere.has(identityOf(f))) continue;
      const key = identityOf(f);
      const existing = resolved.findIndex((r) => identityOf(r) === key);
      const entry = { ...f, resolvedAt: now };
      if (existing >= 0) resolved[existing] = entry; else resolved.unshift(entry);
      changed = true;
    }
    if (!changed) return;
    if (resolved.length > 100) resolved.length = 100;
    await orca.host.call(HOST.STORAGE_SET, { key: 'resolvedFindings', value: resolved }).catch(() => {});
  }

  // 修復/開檔路由：panel 的 readContext 只拿得到 focused worktree 的 terminal，
  // 所以 worker 用 CLI 查出每個 worktree 的 terminal 內嵌進 panel（docs/01 §10）。
  // agent = agent 樣式的 terminal（修復訊息給它）；shell = 一般終端（開檔指令給它）
  const terminalCache = {}; // worktreeId → { at, agent, agentSure, shell }（60s TTL：terminal 會開關、preview 會變，身分要定期重查）
  const TERMINAL_CACHE_MS = 60 * 1000;
  const listTerminalsFor = deps.listTerminalsFor ?? (async (worktreeId) => {
    const path = String(worktreeId).split('::').pop(); // worktreeId 是 repoId::path，selector 用 path:
    if (!path || path === 'manual') return { agent: null, agentSure: false, shell: null };
    const out = await orcaCli(['terminal', 'list', '--worktree', `path:${path}`, '--json']).catch(() => null);
    if (!out) return { agent: null, agentSure: false, shell: null };
    try {
      const terms = JSON.parse(out)?.result?.terminals ?? [];
      return classifyTerminals(terms);
    } catch { return { agent: null, agentSure: false, shell: null }; }
  });

  async function resolveTerminals() {
    for (const wt of Object.keys(memory)) {
      const cached = terminalCache[wt];
      if (cached && now() - cached.at < TERMINAL_CACHE_MS && (cached.agent || cached.shell)) continue;
      terminalCache[wt] = { at: now(), ...(await listTerminalsFor(wt)) };
    }
    return terminalCache;
  }

  // Issue 追蹤：issue body 裡的機器標記 `vibeguard-key:<rule>:<target>`（panel 的
  // buildIssueMessage 會帶上）。worker 用 gh 查各 repo 的 [VibeGuard] issue，
  // 對上標記 → panel 列上顯示 🔗 #N 待修 / ✔ #N 已完成。
  const gh = deps.gh ?? {
    // repo 根 → owner/name（git remote 或 gh 都行，這裡用 gh 統一）
    repoSlug: async (root) => {
      const out = await runCmd(GH_CANDIDATES, ['repo', 'view', '--json', 'nameWithOwner', '-q', '.nameWithOwner'], root).catch(() => null);
      return out?.trim() || null;
    },
    listIssues: async (slug) => {
      const out = await runCmd(GH_CANDIDATES, ['issue', 'list', '--repo', slug, '--search', '[VibeGuard]', '--state', 'all', '--limit', '100', '--json', 'number,title,url,state,body'], null).catch(() => null);
      if (!out) return [];
      try { return JSON.parse(out); } catch { return []; }
    },
  };
  const slugCache = {}; // repoRoot → slug|null
  const issueCache = {}; // slug → { at, issues }
  const ISSUE_CACHE_MS = 60 * 1000;

  async function refreshIssues() {
    const map = {}; // issueKey → { number, url, state }
    const roots = new Set();
    for (const byAgent of Object.values(memory)) {
      for (const list of Object.values(byAgent)) {
        for (const f of list) { const r = findRepoRoot(f.target); if (r) roots.add(r); }
      }
    }
    for (const root of roots) {
      if (!(root in slugCache)) slugCache[root] = await gh.repoSlug(root);
      const slug = slugCache[root];
      if (!slug) continue;
      const hit = issueCache[slug];
      if (!hit || now() - hit.at > ISSUE_CACHE_MS) {
        issueCache[slug] = { at: now(), issues: await gh.listIssues(slug) };
      }
      for (const issue of issueCache[slug].issues) {
        const m = typeof issue.body === 'string' ? issue.body.match(/vibeguard-key:([^\s]+) (.+)/) : null;
        if (m) map[`${m[1]} ${m[2].trim()}`] = { number: issue.number, url: issue.url, state: issue.state };
      }
    }
    return map;
  }

  let dashboardUrl = null; // panel-server 啟動後填入（含 token）
  async function buildPanelData() {
    // 舊 finding（上次 worker 版的記憶體）缺 repoRoot → 重烤時補（面板忽略指令要用）
    for (const byAgent of Object.values(memory)) {
      for (const list of Object.values(byAgent)) {
        for (const f of (Array.isArray(list) ? list : [])) {
          if (f && !f.repoRoot && f.target) f.repoRoot = findRepoRoot(f.target);
        }
      }
    }
    const terminals = await resolveTerminals().catch(() => terminalCache);
    const issues = await refreshIssues().catch(() => ({}));
    const settings = {
      ...(await notifySettings()),
      ...(await llmScanSettings()),
      ...(await localeSettings()),
      ...(await notifyOpenSettings()),
      installMode,
      stateDir,
      stateFile: notifyStateFile,
      llmScanStateFile,
      localeStateFile,
      notifyOpenStateFile,
      dashboardUrl,
      llm: { ...(await llmSettings()), stateFile: llmStateFile },
    };
    return { generatedAt: new Date().toISOString(), groups: memory, scans: scanLog, resolved, terminals, issues, settings };
  }

  // 重烤節流：agent 高頻寫檔時每掃一次就重烤，面板會高頻重掛（閃爍＋watchdog ping
  // 撞上重掛空窗被誤判無響應暫停）。首發直烤，窗內後續合併為尾端一次（資料不漏）。
  const PANEL_BAKE_INTERVAL_MS = deps.panelBakeIntervalMs ?? 5000;
  let lastBakeAt = 0;
  let bakeTimer = null;
  let bakePending = false;
  // 有意義變化才烤：面板更新=remount=閃爍+watchdog 競態，掃描記錄天天在動不值得烤。
  // findings/已修正/issues/設定 變了才烤；純掃描記錄變動搭下次有意義重烤順帶更新。
  // 另設 liveness 重烤（預設 10 分鐘）讓面板心跳警示能分辨 worker 死活。
  const PANEL_LIVENESS_MS = deps.panelLivenessMs ?? 10 * 60 * 1000;
  let lastMeaningfulHash = null;
  let lastBakeWriteAt = 0;
  function meaningfulHash(data) {
    const g = {};
    for (const [wt, byAgent] of Object.entries(data.groups ?? {})) {
      g[wt] = {};
      for (const [ag, list] of Object.entries(byAgent ?? {})) {
        g[wt][ag] = (Array.isArray(list) ? list : []).map((f) => `${identityOf(f)}|${f.severity}`).sort();
      }
    }
    const r = (data.resolved ?? []).map((x) => identityOf(x));
    return JSON.stringify([g, r, data.issues ?? {}, data.settings ?? {}]);
  }
  async function bakeNow() {
    // 安裝版不烤：panel.html 在被驗證完整性的快照目錄裡，改寫它 = Orca 重啟後整個插件載不起來。
    // 安裝版的側欄面板是靜態啟動器（panel.html 內嵌 static:true），資料看 🚀 即時頁。
    if (installMode === 'installed') return;
    const data = await buildPanelData();
    const h = meaningfulHash(data);
    if (h === lastMeaningfulHash && now() - lastBakeWriteAt < PANEL_LIVENESS_MS) return;
    lastMeaningfulHash = h;
    lastBakeWriteAt = now();
    await writePanel(buildPanelHtml(data))
      .catch((err) => orca.log?.(`panel.html 重寫失敗：${err?.message ?? err}`));
  }
  async function refreshPanel() {
    const t = now();
    if (t - lastBakeAt >= PANEL_BAKE_INTERVAL_MS && !bakeTimer) {
      lastBakeAt = t;
      return bakeNow();
    }
    bakePending = true;
    if (!bakeTimer) {
      const wait = Math.max(50, PANEL_BAKE_INTERVAL_MS - (t - lastBakeAt));
      bakeTimer = setTimeout(() => {
        bakeTimer = null;
        if (!bakePending) return;
        bakePending = false;
        lastBakeAt = now();
        bakeNow().catch(() => {});
      }, wait);
      bakeTimer.unref?.();
    }
  }

  // 通知開關（面板上的 Orca 風格 switch 用 shell 指令寫這個檔；worker 每次通知前讀）
  // 內容含 'off' token = 關；其他/不存在 = 開（預設開）
  const notifyStateFile = stateFile('.notify-state');
  // LLM 掃描開關：內容含 'off' = 關（只跑 L1/L2 regex，省 AI 額度）；其餘/不存在 = 開
  const llmScanStateFile = stateFile('.llm-scan-state');
  async function llmScanSettings() {
    const s = await readFile(llmScanStateFile).catch(() => null);
    return { llmScanEnabled: s == null || !s.trim().split(/\s+/).includes('off') };
  }
  // 通知時自動開啟即時頁：內容含 'on' = 開；其餘/不存在 = 關（預設關，會搶焦點）
  const notifyOpenStateFile = stateFile('.notify-open-dashboard');
  async function notifyOpenSettings() {
    const s = await readFile(notifyOpenStateFile).catch(() => null);
    return { notifyOpenDashboard: s != null && s.trim().split(/\s+/).includes('on') };
  }
  async function notifySettings() {
    const s = await readFile(notifyStateFile).catch(() => null);
    return { notify: s == null || !s.trim().split(/\s+/).includes('off') };
  }

  // 通知節流：只叫「還沒通知過的 critical/high」，且全域冷卻 2 分鐘。
  // 冷卻中被擋的 finding 不進 notifiedKeys → 冷卻過後的下一次掃描會補叫。
  const NOTIFY_COOLDOWN_MS = 2 * 60 * 1000;
  let lastNotifyAt = 0;
  const notifiedKeys = new Set();
  const now = deps.now ?? Date.now;

  // agent 活動追蹤（agent.status.changed 帶 paneKey/state，docs/01 §2）。雙重用途：
  // 1) manifest 訂閱它 = agent 一動 host 就拉起 lazy worker（自動喚醒，不用手動指令）
  // 2) findings 的 agent 欄位從 'unknown' 升級成「該 worktree 最近活動的 agent」
  const agentActivity = {}; // worktreeId → { paneKey, at }
  const AGENT_ATTRIBUTION_MS = 10 * 60 * 1000;
  function agentFor(worktreeId) {
    const a = agentActivity[worktreeId];
    return a && a.paneKey && now() - a.at < AGENT_ATTRIBUTION_MS ? String(a.paneKey) : 'unknown';
  }

  // 每 repo 的忽略清單：<repo根>/.vibeguard-ignore（# 註解）。三種粒度：
  //   `rule_id`                → 整條規則不再報
  //   `rule_id <相對路徑>`      → 該檔不檢查這項規則
  //   `rule_id <相對路徑>:<行>`  → 只忽略該檔那行的那一筆
  // 檔案在被監聽的目錄內 → 改它會觸發重掃 → 被忽略的自動消失（進已修正區）
  async function loadIgnored(path) {
    const root = findRepoRoot(path);
    if (!root) return { ruleIds: null, fileRules: null, occurrences: null, root };
    const raw = await readFile(join(root, '.vibeguard-ignore')).catch(() => null);
    if (!raw) return { ruleIds: null, fileRules: null, occurrences: null, root };
    const ruleIds = new Set();
    const fileRules = new Set();
    const occurrences = new Set();
    for (const line of raw.split('\n')) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const sp = t.indexOf(' ');
      if (sp === -1) ruleIds.add(t);
      else if (/:\d+$/.test(t)) occurrences.add(t); // 「rule path:line」
      else fileRules.add(t); // 「rule path」
    }
    return {
      ruleIds: ruleIds.size ? ruleIds : null,
      fileRules: fileRules.size ? fileRules : null,
      occurrences: occurrences.size ? occurrences : null,
      root,
    };
  }

  // 全專案掃描：走訪 worktree 全部支援檔（shouldSkipPath 同一套過濾），逐檔 scanAndReport。
  // LLM 層照現行開關與佇列保護（滿了自動跳過該檔的 LLM，L1/L2 照掃）——不會爆額度。
  const listFilesRecursive = deps.listFilesRecursive ?? (async (root) => {
    const out = [];
    const entries = await fsReaddir(root, { recursive: true, withFileTypes: true }).catch(() => []);
    for (const e of entries) {
      if (!e.isFile()) continue;
      const full = join(e.parentPath ?? e.path ?? root, e.name);
      if (!shouldSkipPath(full)) out.push(full);
    }
    return out;
  });
  let scanAllRunning = false;
  async function scanAllWorktrees() {
    if (scanAllRunning) return { ok: false, reason: 'already-running' };
    scanAllRunning = true;
    (async () => {
      try {
        const roots = watcher.worktreeIds();
        let total = 0;
        for (const root of roots) {
          const files = await listFilesRecursive(root);
          logScan({ kind: 'watch', path: root, worktreeId: root, ...note('noteScanAllStart', { n: files.length }) });
          for (const f of files) {
            await scanAndReport(f, root).catch(() => {});
            total += 1;
          }
          logScan({ kind: 'watch', path: root, worktreeId: root, ...note('noteScanAllDone') });
        }
        orca.log?.(`全專案掃描完成：共 ${total} 檔`);
        await refreshPanel().catch(() => {});
      } finally { scanAllRunning = false; }
    })().catch((err) => orca.log?.(`全專案掃描失敗：${err?.message ?? err}`));
    return { ok: true, ...note('noteScanAllBg') };
  }

  async function scanAndReport(path, worktreeId) {
    try {
      const text = await readFile(path);
      const ignored = await loadIgnored(path);
      const rel = ignored.root ? String(path).slice(ignored.root.length + 1) : null;
      // 誤報學習：載入本 repo 的學習清單。同檔的注入 LLM prompt；整份用於結果後過濾
      let learnedAll = ignored.root
        ? parseLearned(await readFile(join(ignored.root, LEARNED_FILENAME)).catch(() => ''))
        : [];
      const learnedForFile = rel ? learnedAll.filter((e) => e.target === rel) : [];
      const { llmScanEnabled } = await llmScanSettings();
      const { findings: rawFindings, layers, elapsedMs, llmError } = await scanText(
        text, path,
        { l1: true, l2: true, l3: false, llm: llmScanEnabled, ignoreRuleIds: ignored.ruleIds, learned: learnedForFile },
        { llmScan: llmScanEnabled ? gatedLlmScan : null },
      );
      // 檔案級 + 單筆忽略在 scanText 之後過濾（key 用 repo 相對路徑）。
      // 被擋掉的 = 使用者明確略過（🙈/🚫）→ 記進學習清單，下次 LLM 掃描注入 prompt 不再報
      const dismissed = (ignored.fileRules || ignored.occurrences) && rel
        ? rawFindings.filter((f) =>
            (ignored.fileRules?.has(`${f.rule} ${rel}`))
            || (ignored.occurrences?.has(`${f.rule} ${rel}:${f.line}`)))
        : [];
      if (dismissed.length && ignored.root) {
        let next = learnedAll;
        const at = new Date().toISOString();
        for (const f of dismissed) next = addLearned(next, f, rel, at);
        if (next !== learnedAll) {
          learnedAll = next;
          await writeFile(join(ignored.root, LEARNED_FILENAME), serializeLearned(learnedAll))
            .catch((err) => orca.log?.(`學習檔寫入失敗：${err?.message ?? err}`));
        }
      }
      const notIgnored = dismissed.length
        ? rawFindings.filter((f) => !dismissed.includes(f))
        : rawFindings;
      // 學習後過濾：同檔同標題（任何層）直接消失（LLM 層在 llmScan 內已先過一輪）
      const findings = rel && learnedAll.length
        ? notIgnored.filter((f) => !isLearned(f, learnedAll, rel))
        : notIgnored;
      // 分嚴重度記錄：面板燈號要能反映「這次掃到的是嚴重還是注意」——
      // 只看 count 一律亮紅燈，會讓人跑去「嚴重」區白找（實際全在「注意」折疊區裡）
      const sev = {};
      for (const f of findings) if (f.severity) sev[f.severity] = (sev[f.severity] ?? 0) + 1;
      logScan({ kind: 'scan', path, worktreeId, count: findings.length, sev, layers, elapsedMs, ...(llmError ? { llmError } : {}) });
      orca.log?.(`掃描 ${path}：${findings.length} 個問題（${layers.join('+')}，${elapsedMs}ms）`);
      const agent = agentFor(worktreeId);
      if (findings.length) {
        const foundAt = new Date().toISOString();
        for (const f of findings) {
          f.worktreeId = worktreeId;
          f.agent = agent;
          f.foundAt = foundAt;
          if (rel) f.ignoreKey = `${f.rule} ${rel}:${f.line}`; // 單筆忽略用的 .vibeguard-ignore 行
          if (ignored.root) f.repoRoot = ignored.root; // 面板忽略指令要直接寫該 repo 的 .vibeguard-ignore
          // 代碼片段（±1 行、redactForLlm 遮蔽）：開檔不能跳行（CLI 無 --line），把代碼帶到面板
          if (Number.isInteger(f.line) && f.line > 0) {
            const srcLines = String(text).split('\n');
            const from = Math.max(1, f.line - 1);
            const seg = redactForLlm(srcLines.slice(from - 1, Math.min(srcLines.length, f.line + 1)).join('\n')).text.split('\n');
            f.snippet = seg.map((t, i) => ({ ln: from + i, text: t.slice(0, 200) }));
          }
        }
        assignIdentities(findings); // 身分要在 snippet 之後算（指紋看命中行的內容）
      }
      await markResolved(path, findings); // 記已修正（讀 merge 前的 memory；身分已就緒）
      if (findings.length) {
        // 只通知「還沒通知過的 critical/high」，且全域 2 分鐘最多一次
        const newSerious = findings.filter((f) => !notifiedKeys.has(identityOf(f)) && (f.severity === 'critical' || f.severity === 'high'));
        const nst = await notifySettings();
        if (newSerious.length && now() - lastNotifyAt >= NOTIFY_COOLDOWN_MS && nst.notify) {
          lastNotifyAt = now();
          for (const f of newSerious) notifiedKeys.add(identityOf(f));
          const crit = newSerious.filter((f) => f.severity === 'critical').length;
          const name = String(path).split(/[\\/]/).pop();
          const { resolvedLocale } = await localeSettings();
          await orca.host.call(HOST.NOTIFY, {
            title: t(resolvedLocale, 'notifyTitle').slice(0, 120),
            body: t(resolvedLocale, 'notifyBody', { name, crit, total: newSerious.length }).slice(0, 1000),
          }).catch(() => {});
          // 使用者要「有通知時跳出來」：安裝版側欄面板不會自動更新，所以順便開（或切到）即時頁
          const { notifyOpenDashboard } = await notifyOpenSettings();
          if (notifyOpenDashboard && dashboardUrl) await orcaCli(['goto', '--url', dashboardUrl]).catch(() => {});
        }
      }
      // 無論有無發現都更新（乾淨重掃 = 清掉該檔舊 findings）
      await persistFindings(worktreeId, agent, findings, path).catch((err) => orca.log?.(`storage 失敗：${err?.message ?? err}`));
      // 無論有無發現都重寫 panel（掃描記錄要可見）
      await refreshPanel();
      return findings;
    } catch (err) {
      // 暫存檔在 watch 事件到讀檔之間被刪（agent 狀態檔常見）——記「跳過」而非錯誤
      const isGone = err?.code === 'ENOENT' || String(err?.message ?? '').includes('ENOENT');
      logScan(isGone
        ? { kind: 'skip', path, worktreeId, ...note('noteSkipGone') }
        : { kind: 'scan', path, worktreeId, error: String(err?.message ?? err) });
      if (isGone) {
        // 檔案不存在 = 問題不存在：比照「乾淨重掃」清掉該檔舊 findings（進已修正），
        // 否則刪檔後 finding 永遠殘留在面板
        await markResolved(path, []);
        await persistFindings(worktreeId, 'unknown', [], path).catch(() => {});
      }
      await refreshPanel();
      if (isGone) return [];
      throw err;
    }
  }

  // .vibeguard-ignore 變動（使用者按「忽略這筆/此檔免檢」後 agent 寫入）→ 重新套用規則：
  // 命中規則的現行 finding 從清單移除、進已修正、學進 .vibeguard-learned.json（誤報學習 ISSUE-12）
  async function applyIgnoreFile(ignorePath, worktreeId) {
    try {
      const ignored = await loadIgnored(ignorePath);
      if (!ignored.root) return;
      let learnedAll = parseLearned(await readFile(join(ignored.root, LEARNED_FILENAME)).catch(() => ''));
      let learnedChanged = false;
      const at = new Date().toISOString();
      let removed = 0;
      for (const byAgent of Object.values(memory)) {
        for (const [agent, list] of Object.entries(byAgent)) {
          const kept = [];
          for (const f of (Array.isArray(list) ? list : [])) {
            const target = String(f.target ?? '');
            if (!target.startsWith(ignored.root + '/')) { kept.push(f); continue; }
            const rel2 = target.slice(ignored.root.length + 1);
            const hit = (ignored.ruleIds?.has(f.rule))
              || (ignored.fileRules?.has(`${f.rule} ${rel2}`))
              || (ignored.occurrences?.has(`${f.rule} ${rel2}:${f.line}`));
            if (!hit) { kept.push(f); continue; }
            removed += 1;
            const idx = resolved.findIndex((r) => resolvedKey(r) === resolvedKey(f));
            const entry = { ...f, resolvedAt: at };
            if (idx >= 0) resolved[idx] = entry; else resolved.unshift(entry);
            const next = addLearned(learnedAll, f, rel2, at);
            if (next !== learnedAll) { learnedAll = next; learnedChanged = true; }
          }
          byAgent[agent] = kept;
        }
      }
      if (!removed) return; // 規則沒命中任何現行 finding，不用動
      if (learnedChanged) {
        await writeFile(join(ignored.root, LEARNED_FILENAME), serializeLearned(learnedAll))
          .catch((err) => orca.log?.(`學習檔寫入失敗：${err?.message ?? err}`));
      }
      await orca.host.call(HOST.STORAGE_SET, { key: 'findings', value: memory }).catch(() => {});
      await orca.host.call(HOST.STORAGE_SET, { key: 'resolvedFindings', value: resolved }).catch(() => {});
      logScan({ kind: 'skip', path: ignorePath, worktreeId, ...note('noteIgnoreApplied', { n: removed }) });
      await refreshPanel();
    } catch (err) {
      orca.log?.(`套用忽略規則失敗：${err?.message ?? err}`);
    }
  }

  const watcher = deps.watcher ?? new WorktreeWatcher({
    onFileReady: (e) => { scanAndReport(e.path, e.worktreeId).catch((err) => orca.log?.(`scan 失敗：${err?.message ?? err}`)); },
    onIgnoreChanged: (e) => { applyIgnoreFile(e.path, e.worktreeId).catch(() => {}); },
    debounceMs: deps.watchDebounceMs ?? 2000,
    deps: deps.watcherDeps,
  });

  // panel.html 原子重寫（先寫 tmp 再 rename，避免 panel 讀到半截）
  const writePanel = deps.writePanel ?? (async (html) => {
    const panelPath = fileURLToPath(new URL('./panel.html', import.meta.url));
    const tmp = panelPath + '.tmp';
    await fsWriteFile(tmp, html, 'utf8');
    await fsRename(tmp, panelPath);
  });

  // worker 是 lazy 啟動（docs/01 §9）：啟動前已存在的 worktree 不會有事件，
  // 所以 scanFile 時順手把該檔所屬 repo 根目錄加進 watcher（往上找 .git）
  const findRepoRoot = deps.findRepoRoot ?? ((p) => {
    let dir = dirname(String(p));
    for (let i = 0; i < 20 && dir && dir !== dirname(dir); i += 1) {
      if (existsSync(join(dir, '.git'))) return dir;
      dir = dirname(dir);
    }
    return null;
  });

  // worktree 追蹤
  orca.events.on('agent.status.changed', (p) => {
    if (p?.worktreeId && p?.paneKey) agentActivity[p.worktreeId] = { paneKey: p.paneKey, at: now() };
  });
  orca.events.on('worktree.created', (p) => {
    if (p?.worktreeId && p?.path) {
      watcher.addWorktree(p.worktreeId, p.path);
      logScan({ kind: 'watch', path: p.path, worktreeId: p.worktreeId, ...note('noteWatchStart') });
    }
  });
  orca.events.on('worktree.removed', (p) => {
    if (p?.worktreeId) {
      watcher.removeWorktree(p.worktreeId);
      logScan({ kind: 'unwatch', path: p.path ?? '', worktreeId: p.worktreeId, ...note('noteUnwatch') });
    }
  });
  await orca.host.call(HOST.EVENTS_SUBSCRIBE, { events: ['worktree.created', 'worktree.removed', 'agent.status.changed'] }).catch(() => {});

  // 啟動自清：worker 停擺期間被刪的檔不會再有事件，其 findings 會永久殘留——啟動時 stat 一輪
  {
    let pruned = 0;
    for (const [wt, byAgent] of Object.entries(memory)) {
      for (const [agentKey, list] of Object.entries(byAgent)) {
        const kept = [];
        for (const f of (Array.isArray(list) ? list : [])) {
          if (await fileExists(f?.target ?? '')) kept.push(f);
          else pruned += 1;
        }
        if (kept.length) byAgent[agentKey] = kept;
        else delete byAgent[agentKey];
      }
      if (!Object.keys(byAgent).length) delete memory[wt];
    }
    if (pruned) orca.log?.(`啟動自清：移除 ${pruned} 筆已刪檔案的 finding`);
  }

  // 既有 worktree 補救（lazy 啟動收不到它們的 created 事件）：worker 是無沙箱 Node，
  // 用 `orca worktree list --json` 拉出全部既有 worktree 一次納入監聽。
  // 注意：不能卡在 activate 裡等它——activation 進行中若 host 做 refresh（dev watcher
  // 看到 .git / panel.html 變動），isCurrentApproved 的參照比對會失敗，worker 會在
  // activate 完成當下被 deactivate（實測 activate end 後 1ms 被殺）。所以延後跑。
  const listManagedWorktrees = deps.listManagedWorktrees ?? (async () => {
    const out = await orcaCli(['worktree', 'list', '--json']).catch(() => null);
    if (!out) return [];
    try {
      const list = JSON.parse(out)?.result?.worktrees ?? [];
      return list.map((w) => w.path).filter(Boolean);
    } catch { return []; }
  });
  const scheduleDeferred = deps.scheduleDeferred ?? ((fn) => setTimeout(fn, 0));

  // keepalive：防閒置 reap
  const keepalive = setInterval(() => { orca.host.call(HOST.STORAGE_KEYS, {}).catch(() => {}); }, KEEPALIVE_MS);
  keepalive.unref?.();

  // 一鍵修復：組訊息送到 focused worktree 的第一個 terminal（給跑著的 Claude 看）
  async function fixFinding(finding = {}) {
    // 只接受 memory 裡確實存在的 finding（rule+target+line 比對），
    // 不照單全收呼叫端傳入的任意物件；訊息用存著的版本組（欄位已消毒）
    const key = resolvedKey(finding);
    let stored = null;
    for (const byAgent of Object.values(memory)) {
      for (const list of Object.values(byAgent)) {
        const hit = list.find((f) => resolvedKey(f) === key);
        if (hit) { stored = hit; break; }
      }
      if (stored) break;
    }
    if (!stored) return { ok: false, reason: 'not-found' };
    const ctx = await orca.host.call(HOST.READ_CONTEXT, {});
    const terminalId = ctx?.terminals?.[0]?.id;
    if (!terminalId) return { ok: false, reason: 'no-terminal' };
    const { resolvedLocale } = await localeSettings();
    // 安全：focused terminal 可能是 shell → 不自動 Enter，讓使用者確認後再送出
    await orca.host.call(HOST.TERMINAL_SEND, { terminalId, text: buildFixMessage(stored, resolvedLocale), enter: false });
    return { ok: true };
  }

  async function getGroupedFindings() {
    return memory; // 記憶體為主（ISSUE-11）；storage 只是持久化副本
  }

  // 開檔：Orca 無 openFile host method（docs/01 §1），走 CLI（無 --line 參數）
  const openFile = deps.openFile ?? (async (path, worktreeId) => {
    const args = ['file', 'open', path];
    if (worktreeId) args.push('--worktree', worktreeId);
    await orcaCli(args);
  });

  // 指令
  orca.commands.register('vibeguard.scanFile', async (args = {}) => {
    if (!args.path) return { ok: false, reason: 'no-path' };
    // 安全：只掃 git repo 內的檔案（擋「任意路徑讀取並外送 LLM」，dogfooding 發現）
    const root = findRepoRoot(args.path);
    if (!root) return { ok: false, reason: 'outside-repo' };
    // 順手把該檔所屬 repo 根加進 watcher（lazy 啟動前的舊 worktree 不會有事件）
    if (!watcher.worktreeIds().includes(args.worktreeId ?? root)) {
      watcher.addWorktree(args.worktreeId ?? root, root);
      logScan({ kind: 'watch', path: root, worktreeId: args.worktreeId ?? root, ...note('noteWatchStartScanFile') });
    }
    return scanAndReport(args.path, args.worktreeId ?? 'manual');
  });

  orca.commands.register('vibeguard.fix', fixFinding);

  orca.commands.register('vibeguard.scanAll', async () => scanAllWorktrees());

  orca.commands.register('vibeguard.status', async () => {
    const all = await getGroupedFindings();
    let findingsCount = 0;
    for (const byAgent of Object.values(all)) {
      for (const list of Object.values(byAgent)) findingsCount += list.length;
    }
    return { watched: watcher.worktreeIds(), findingsCount };
  });

  // 即時 dashboard 動作端：dashboard 頁的按鈕全走這裡（worker 端直接執行，
  // 不借道 terminal 打 shell 指令）。防偽造：finding 類動作只認 memory 裡存在的
  function findStored(ref = {}) {
    const key = `${ref.rule} ${ref.target} ${ref.line}`;
    for (const byAgent of Object.values(memory)) {
      for (const list of Object.values(byAgent)) {
        const hit = (Array.isArray(list) ? list : []).find((f) => resolvedKey(f) === key);
        if (hit) return hit;
      }
    }
    return null;
  }
  const doAction = deps.doAction ?? (async (body = {}) => {
    const kind = String(body.kind ?? '');
    if (kind === 'llmScan') {
      await writeFile(llmScanStateFile, body.value === 'off' ? 'off' : 'on');
      await refreshPanel();
      return { ok: true };
    }
    if (kind === 'scanAll') {
      return scanAllWorktrees();
    }
    if (kind === 'notify') {
      await writeFile(notifyStateFile, body.value === 'off' ? 'off' : 'on');
      await refreshPanel();
      return { ok: true };
    }
    if (kind === 'notifyOpenDashboard') {
      await writeFile(notifyOpenStateFile, body.value === 'on' ? 'on' : 'off');
      await refreshPanel();
      return { ok: true };
    }
    if (kind === 'locale') {
      // 只收 'auto' 或 i18n.mjs 有的語系 id（值會落檔，不能讓任意字串進來）
      const v = String(body.value ?? 'auto').trim();
      if (v !== 'auto' && !LOCALES[v]) return { ok: false, reason: 'unknown-locale' };
      await writeFile(localeStateFile, v);
      await localeSettings();
      await refreshPanel();
      return { ok: true };
    }
    if (kind === 'llm') {
      const fw = String(body.framework ?? 'claude');
      if (!LLM_FRAMEWORKS.includes(fw)) return { ok: false, reason: 'unknown-framework' };
      const model = String(body.model ?? '').replace(/[^\w.\-]/g, '').slice(0, 64);
      await writeFile(llmStateFile, model ? `${fw}:${model}` : fw);
      await refreshPanel();
      return { ok: true };
    }
    if (kind === 'restart') {
      // 2026-08-31 教訓：worker 自己 exit 會被 host 記進 maxRestarts=3 的失敗額度，
      // 額度用完插件整個標 errored、所有事件被丟（實際發生，只有設定頁 toggle 能救）。
      // 所以這裡絕不 exit——誠實告訴使用者唯一安全的重啟方式。
      return { ok: false, reason: 'needs-toggle', ...note('noteNeedsToggle') };
    }
    const stored = findStored(body);
    if (!stored) {
      // 冪等：finding 已被先前同類請求移除 → 若 ignore 檔已有對應條目，回「已處理」而非 not-found
      if (kind === 'ignore' || kind === 'dismiss') {
        const root = findRepoRoot(String(body.target ?? ''));
        if (root) {
          const rel = String(body.target).startsWith(root) ? String(body.target).slice(root.length + 1) : String(body.target);
          const lnB = Number.isInteger(body.line) ? body.line : Number.parseInt(body.line, 10);
          const wants = kind === 'dismiss' && Number.isInteger(lnB)
            ? [`${body.rule} ${rel}:${lnB}`, `${body.rule} ${rel}`]
            : [`${body.rule} ${rel}`];
          const cur = String(await readFile(join(root, '.vibeguard-ignore')).catch(() => ''));
          const lines = cur.split('\n').map((l) => l.trim());
          if (wants.some((w) => lines.includes(w))) return { ok: true, already: true };
        }
      }
      return { ok: false, reason: 'not-found' };
    }
    if (kind === 'open') {
      const wtPath = String(stored.worktreeId ?? '').split('::').pop();
      await openFile(stored.target, wtPath && stored.worktreeId !== 'manual' ? `path:${wtPath}` : undefined);
      return { ok: true };
    }
    if (kind === 'ignore' || kind === 'dismiss') {
      if (!stored.repoRoot) return { ok: false, reason: 'no-repo-root' };
      const rel = String(stored.target).startsWith(stored.repoRoot)
        ? String(stored.target).slice(String(stored.repoRoot).length + 1)
        : String(stored.target);
      // 行號可能是字串（LLM 回傳）——轉整數；真的沒有就降級整檔（':?' 這種條目比對端永遠不認，等於白寫）
      const ln = Number.isInteger(stored.line) ? stored.line : Number.parseInt(stored.line, 10);
      const entry = (kind === 'dismiss' && Number.isInteger(ln))
        ? `${stored.rule} ${rel}:${ln}`
        : `${stored.rule} ${rel}`;
      await appendFile(join(stored.repoRoot, '.vibeguard-ignore'), entry + '\n');
      return { ok: true };
    }
    if (kind === 'fix' || kind === 'issue') {
      const { resolvedLocale } = await localeSettings();
      const message = kind === 'fix' ? buildFixMessage(stored, resolvedLocale) : buildIssueMessage(stored, resolvedLocale);
      // 跨 worktree 只能走 CLI（host.call 限 focused worktree）；agentSure 才自動 Enter
      const term = await listTerminalsFor(stored.worktreeId).catch(() => null);
      if (term?.agent) {
        const args = ['terminal', 'send', '--terminal', term.agent, '--text', message];
        if (term.agentSure !== false) args.push('--enter');
        await orcaCli(args);
        return term.agentSure === false
          ? { ok: true, ...note('noteAgentUnsure') }
          : { ok: true };
      }
      // 不落回 focused terminal：focused 可能是別的專案的 agent（實際發生：A 專案的修法打進 B 專案的 agent）
      return { ok: false, reason: 'no-agent-terminal', ...note('noteNoAgentTerminal') };
    }
    return { ok: false, reason: 'unknown-action' };
  });

  // 即時 dashboard 通道：panel 沙箱不能 fetch，但 Orca 內嵌瀏覽器（orca goto）可以——
  // dashboard 頁由本 server 供應，每 2 秒輪詢 /api/state（token 驗證，見 panel-server.mjs）
  // token 持久化：重啟就換 token 會讓已掛載面板/使用者複製的 curl 全部 bad token
  // （實際發生：免檢按了沒效）。首次生成存檔，之後重啟沿用同一顆。

  const panelServer = deps.panelServer ?? await startPanelServer({
    token: dashToken,
    getState: buildPanelData,
    doAction,
    dashboardHtml: buildDashboardHtml,
    openFile,
    fixFinding,
    getGroupedFindings,
    log: (m) => orca.log?.(m),
  }).catch((err) => { orca.log?.(`panel server 啟動失敗：${err?.message ?? err}`); return null; });
  if (panelServer) {
    dashboardUrl = `${panelServer.url}/?token=${dashToken}`;
    orca.log?.(`panel server: ${panelServer.url}`);
    // 安裝版的靜態面板拿不到內嵌設定：把位址落到 stateDir，面板指令用 $(cat …) 在 shell 端展開
    await writeFile(stateFile('dashboard-url'), dashboardUrl).catch(() => {});
    await writeFile(stateFile('api-url'), `${panelServer.url}/api/action?token=${dashToken}`).catch(() => {});
  }

  active = { watcher, keepalive, panelServer, backfillTimer: null };
  // backfill 必須排在 active 設定「之後」：它開頭的 `if (!active) return` 防的是 deactivate，
  // 但若在這行之前排程，activate 尾段任何 await（如真 panelServer 的 listen）都會讓
  // timer 搶跑在 active=null 時執行而靜默自殺（既有 worktree 沒被納管）。bisect 實證。
  active.backfillTimer = scheduleDeferred(async () => {
    if (!active) return; // 已 deactivate 就不補
    try {
      const paths = await listManagedWorktrees();
      for (const p of paths) {
        if (watcher.worktreeIds().includes(p)) continue;
        watcher.addWorktree(p, p);
        logScan({ kind: 'watch', path: p, worktreeId: p, ...note('noteWatchStartExisting') });
      }
      await refreshPanel(); // 無論有無補到都重寫（磁碟上的 panel 可能是舊模板/舊資料）
    } catch (err) {
      orca.log?.(`backfill 失敗：${err?.message ?? err}`);
    }
  });
  crashAppend(`[${new Date().toISOString()}] activate end`);
}

export function deactivate() {
  crashAppend(`[${new Date().toISOString()}] deactivate called`);
  if (!active) return;
  clearInterval(active.keepalive);
  clearTimeout(active.backfillTimer);
  active.watcher.dispose();
  active.panelServer?.close();
  active = null;
}
