// dashboard.mjs — 即時 dashboard 頁（跑在 Orca 內嵌瀏覽器，orca goto 開啟）。
//
// 與 panel.html 的差別：panel 是 sandboxed iframe（CSP 禁 fetch，資料開啟當下內嵌）；
// 這頁是 panel-server 供應的普通網頁，每 2 秒輪詢 /api/state → 真即時、不重刷頁面。
// 動作（開檔/修復/開 Issue/忽略/設定/語言）全走 POST /api/action，由 worker 端執行——
// 不再借道 terminal 打 shell 指令，比 panel 的 bridge 更直接。
//
// i18n：與 panel 同一份字典（i18n.mjs）整包內嵌；偏好 localStorage vgd.lang → worker .locale → navigator.language。
//
// 紀律（與 panel-renderer 相同）：本檔 script 區在 template literal 裡，
// 一律避免 regex（反斜線會被吃掉）；換行字串寫 '\\n'。驗收：測試抽 <script> 做 new Function。

import { localePack } from './i18n.mjs';
import { safeInlineJson } from './panel-renderer.mjs';

export function buildDashboardHtml() {
  return TEMPLATE_HEAD + safeInlineJson(localePack()) + TEMPLATE_TAIL;
}

const TEMPLATE_HEAD = `<!doctype html>
<html lang="zh-Hant">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeGuard</title>
<style>
  :root {
    color-scheme: light dark;
    --bg: #fbfbfc; --fg: #1b1e24; --muted: #70757e;
    --line: rgba(125,132,148,.28); --card: rgba(125,132,148,.07); --card-2: rgba(125,132,148,.14);
    --crit: #e5484d; --warn: #d98a1c; --ok: #2f9e6b; --accent: #3b82f6;
    --crit-soft: rgba(229,72,77,.10); --accent-soft: rgba(59,130,246,.14);
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #121419; --fg: #e7e9ee; --muted: #8d939e;
      --line: rgba(148,158,178,.20); --card: rgba(148,158,178,.09); --card-2: rgba(148,158,178,.16);
      --warn: #e6a13c;
    }
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, "Segoe UI", sans-serif;
    margin: 0; padding: 0 0 40px;
    background: var(--bg); color: var(--fg);
    font-size: 13px; line-height: 1.45;
    -webkit-font-smoothing: antialiased;
    font-variant-numeric: tabular-nums;
  }
  .wrap { max-width: 860px; margin: 0 auto; padding: 14px 18px; }
  button, select { font: inherit; color: inherit; }
  button:focus-visible, select:focus-visible, summary:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
  .loc, .scan { font-family: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace; }
  /* ── 頂欄（sticky，含連線狀態）── */
  .topbar { position: sticky; top: 0; z-index: 5; background: var(--bg); box-shadow: 0 1px 0 var(--line); }
  .topbar .in { max-width: 860px; margin: 0 auto; padding: 10px 18px; display: flex; align-items: center; gap: 8px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: var(--muted); flex: none; transition: background .3s; }
  .dot.live { background: var(--ok); box-shadow: 0 0 6px rgba(47,158,107,.6); }
  .dot.dead { background: var(--crit); }
  h1 { margin: 0; font-size: 15px; font-weight: 700; letter-spacing: -.01em; }
  .sub { color: var(--muted); font-size: 11px; }
  #unread { margin-left: auto; font-size: 11px; color: var(--accent); flex: none; }
  #unread:not(:empty) { background: var(--accent-soft); border-radius: 999px; padding: 2px 9px; font-weight: 600; }
  #status { font-size: 11px; color: var(--muted); margin: 8px 0 10px; min-height: 14px; word-break: break-all; }
  /* ── KPI ── */
  #summary { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }
  .kpi { border: 1px solid var(--line); background: var(--card); border-radius: 10px; padding: 10px 13px 9px; }
  .kpi .n { font-size: 24px; font-weight: 700; letter-spacing: -.02em; line-height: 1.15; }
  .kpi .l { font-size: 11px; color: var(--muted); margin-top: 1px; }
  .kpi.crit .n { color: var(--crit); } .kpi.warn .n { color: var(--warn); } .kpi.ok .n { color: var(--ok); }
  .kpi.zero .n { color: var(--muted); opacity: .55; }
  #meta { color: var(--muted); font-size: 11px; margin-top: 8px; }
  /* ── chips ── */
  .chips { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; padding: 10px 0 4px; }
  .chips .gap { flex: 1; }
  .chip { border: 1px solid var(--line); border-radius: 999px; padding: 3px 11px; background: transparent;
    cursor: pointer; font-size: 12px; white-space: nowrap; flex: none;
    transition: background .15s, border-color .15s, transform .06s; }
  .chip:hover { background: var(--card-2); }
  .chip:active { transform: scale(.96); }
  .chip.active { background: var(--accent-soft); border-color: transparent; color: var(--accent); font-weight: 600; }
  /* ── 設定卡 ── */
  .card { border: 1px solid var(--line); border-radius: 12px; background: var(--card); margin: 10px 0 2px; }
  .card .body { padding: 0 12px 4px; }
  summary { list-style: none; cursor: pointer; font-weight: 600; font-size: 12px;
    display: flex; align-items: center; gap: 6px; padding: 7px 9px; border-radius: 9px;
    transition: background .15s; word-break: break-all; }
  summary::-webkit-details-marker { display: none; }
  summary::before { content: '▸'; color: var(--muted); font-size: 10px; flex: none; transition: transform .15s; }
  details[open] > summary::before { transform: rotate(90deg); }
  summary:hover { background: var(--card-2); }
  .card > summary { padding: 8px 12px; border-radius: 12px; }
  .sum-hint { color: var(--muted); font-weight: 400; font-size: 11px; margin-left: 2px; }
  .setting-row { display: flex; align-items: center; justify-content: space-between; gap: 10px;
    padding: 8px 0; font-size: 12px; border-top: 1px solid var(--line); }
  .switch { position: relative; display: inline-block; width: 36px; height: 20px; flex: none; }
  .switch input { opacity: 0; width: 0; height: 0; }
  .slider { position: absolute; inset: 0; background: var(--card-2); border: 1px solid var(--line);
    border-radius: 20px; transition: .2s; cursor: pointer; }
  .slider::before { content: ''; position: absolute; width: 14px; height: 14px; left: 2px; top: 2px;
    background: #fff; border-radius: 50%; transition: .2s; box-shadow: 0 1px 2px rgba(0,0,0,.25); }
  .switch input:checked + .slider { background: var(--accent); border-color: transparent; }
  .switch input:checked + .slider::before { transform: translateX(16px); }
  .vg-select-wrap { position: relative; display: inline-block; }
  .vg-select-wrap::after { content: '▾'; position: absolute; right: 9px; top: 50%; transform: translateY(-50%);
    pointer-events: none; color: var(--muted); font-size: 11px; }
  .vg-select { appearance: none; -webkit-appearance: none; background: var(--card);
    border: 1px solid var(--line); border-radius: 8px; font-size: 12px;
    padding: 5px 24px 5px 10px; min-height: 28px; cursor: pointer; }
  .llm-picker { display: inline-flex; gap: 6px; flex: none; }
  /* ── 分區/卡片 ── */
  .sec { display: flex; align-items: center; gap: 7px; font-weight: 650; margin: 16px 0 2px; font-size: 12.5px; }
  .sec::before { content: ''; width: 8px; height: 8px; border-radius: 3px; flex: none; }
  .sec.serious { color: var(--crit); } .sec.serious::before { background: var(--crit); }
  .sec.normal { color: var(--warn); } .sec.normal::before { background: var(--warn); }
  details { margin-top: 4px; }
  details .row { margin-left: 14px; }
  .row { position: relative; border: 1px solid var(--line); border-radius: 10px;
    padding: 8px 10px 7px 13px; margin-top: 6px; background: var(--card);
    transition: background .15s; }
  .row::before { content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px;
    border-radius: 0 3px 3px 0; background: var(--muted); }
  .row:hover { background: var(--card-2); }
  .row.critical::before, .row.high::before { background: var(--crit); }
  .row.medium::before { background: var(--warn); }
  .row.low::before { background: var(--ok); }
  .title { display: flex; flex-direction: column; gap: 5px; font-weight: 600; font-size: 12.5px; }
  .btns { display: flex; gap: 5px; flex-wrap: wrap; }
  .btn { border: 1px solid var(--line); border-radius: 7px; background: transparent;
    padding: 2px 8px; cursor: pointer; font-size: 11px; font-weight: 400; white-space: nowrap;
    transition: background .15s, transform .06s; }
  .btn:hover { background: var(--card-2); }
  .btn:active { transform: scale(.96); }
  .btn:disabled { opacity: .5; cursor: default; }
  .desc { font-size: 12px; font-weight: 400; margin-top: 3px; word-break: break-all; opacity: .85; line-height: 1.5; }
  .badge-new { display: inline-block; background: var(--accent); color: #fff; border-radius: 6px;
    font-size: 9.5px; font-weight: 700; letter-spacing: .03em; padding: 1px 5px; margin-right: 6px; vertical-align: 1px; }
  .loc { font-size: 10.5px; color: var(--muted); margin-top: 4px; word-break: break-all; }
  .snippet { font-family: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px; line-height: 1.6; background: var(--card-2); border: 1px solid var(--line);
    border-radius: 8px; padding: 6px 9px; margin: 5px 0 0; overflow-x: auto; white-space: pre; }
  #empty-state { text-align: center; padding: 44px 12px 34px; color: var(--muted); }
  #empty-state svg { color: var(--ok); opacity: .9; margin-bottom: 10px; }
  #empty-state .t { font-size: 13px; font-weight: 600; color: var(--fg); }
  #empty-state .s { font-size: 11.5px; margin-top: 3px; }
  .scan { font-size: 10.5px; color: var(--muted); margin: 3px 0 0 14px; word-break: break-all; }
  ::-webkit-scrollbar { width: 10px; }
  ::-webkit-scrollbar-thumb { background: var(--line); border-radius: 8px;
    border: 3px solid transparent; background-clip: content-box; }
  @media (prefers-reduced-motion: reduce) { *, *::before, *::after { transition: none !important; } }
</style>
</head>
<body>
<header class="topbar"><div class="in">
  <span class="dot" id="live-dot" data-i18n-title="liveDotTitle" title="連線狀態"></span>
  <svg width="18" height="18" viewBox="0 0 24 24" style="color: var(--accent); flex: none" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"></path><path d="m8.6 12.2 2.3 2.4 4.5-4.7" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"></path></svg>
  <h1>VibeGuard</h1>
  <span class="sub" data-i18n="dashSubtitle">即時安全總覽</span>
  <span id="unread"></span>
</div></header>
<div class="wrap">
<div id="status"></div>
<div id="summary"></div>
<div id="meta"></div>
<div class="chips" id="chips">
  <button class="chip active" data-f="all" type="button" data-i18n="chipAll">全部</button>
  <button class="chip" data-f="serious" type="button" data-i18n="chipSerious">僅嚴重</button>
  <button class="chip" data-f="normal" type="button" data-i18n="chipNormal">僅注意</button>
  <span class="gap"></span>
  <button class="chip" id="mark-all-read" type="button" data-i18n="markAllRead">✓ 全部已讀</button>
</div>
<details class="card" id="settings-card">
  <summary><span data-i18n="settings">⚙️ 設定</span><span class="sum-hint" data-i18n="dashSettingsHint">通知・L3 LLM・語言</span></summary>
  <div class="body">
    <div class="setting-row" data-i18n-title="notifyToggleTitle" title="嚴重問題的桌面通知；關掉後照樣掃、照樣記錄，只是不跳通知">
      <span data-i18n="notifyToggle">🔔 啟用通知</span>
      <label class="switch"><input type="checkbox" id="notify-toggle"><span class="slider"></span></label>
    </div>
    <div class="setting-row" data-i18n-title="llmPickerTitle" title="背景掃描用的 LLM（便宜模型即可）">
      <span data-i18n="llmPicker">🧠 L3 語意審查</span>
      <span class="llm-picker">
        <span class="vg-select-wrap"><select id="llm-framework" class="vg-select">
          <option value="claude">claude</option>
          <option value="codex">codex</option>
          <option value="gemini">gemini</option>
        </select></span>
        <span class="vg-select-wrap"><select id="llm-model" class="vg-select"></select></span>
      </span>
    </div>
    <div class="setting-row" data-i18n-title="langTitle" title="介面語言；「自動」跟隨系統語言">
      <span data-i18n="langLabel">🌐 語言</span>
      <span class="vg-select-wrap"><select id="lang-select" class="vg-select"></select></span>
    </div>
  </div>
</details>
<div id="main"></div>
<div id="empty-state" hidden>
  <svg width="44" height="44" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3z" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linejoin="round"></path><path d="m8.6 12.2 2.3 2.4 4.5-4.7" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"></path></svg>
  <div class="t" data-i18n="emptyTitle">目前沒有發現問題</div>
  <div class="s" data-i18n="dashEmptySub">即時監控中——有檔案變動就會自動掃描並更新這頁</div>
</div>
<div id="resolved"></div>
<div id="scanlog"></div>
</div>
<script>
'use strict';
const I18N = `;

const TEMPLATE_TAIL = `;
const TOKEN = new URLSearchParams(location.search).get('token') || '';
const SERIOUS = ['critical', 'high'];
let DATA = { groups: {}, scans: [], resolved: [] };
let lastJson = '';

// ── 檢視狀態（localStorage，key 用 vgd. 前綴與 panel 區隔）──
const LS = {
  get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* ignore */ } },
};

// ── i18n（與 panel-renderer / i18n.mjs 同邏輯，不用 regex）──
function resolveLang(pref, sys) {
  const p = String(pref == null ? '' : pref).trim().toLowerCase();
  for (const id of Object.keys(I18N.locales)) if (id.toLowerCase() === p) return id;
  const s = String(sys == null ? '' : sys).trim().split('_').join('-').toLowerCase();
  if (!s) return I18N.fallback;
  const parts = s.split('-');
  const lang = parts[0];
  if (lang === 'zh') {
    const trad = parts.indexOf('hant') !== -1 || parts.indexOf('tw') !== -1 || parts.indexOf('hk') !== -1 || parts.indexOf('mo') !== -1;
    return trad ? 'zh-TW' : 'zh-CN';
  }
  if (lang === 'ja') return 'ja';
  if (lang === 'en') return 'en';
  return I18N.fallback;
}
function langPref() {
  const saved = LS.get('vgd.lang', null);
  if (saved) return saved;
  const fromWorker = DATA.settings && DATA.settings.locale;
  return fromWorker || 'auto';
}
let LANG = resolveLang(langPref(), navigator.language || '');
function t(key, params) {
  const dict = I18N.locales[LANG] || I18N.locales[I18N.default];
  const base = I18N.locales[I18N.default];
  const tpl = (dict && dict[key] != null) ? dict[key] : ((base && base[key] != null) ? base[key] : key);
  if (!params) return tpl;
  let out = '';
  let i = 0;
  for (;;) {
    const a = tpl.indexOf('{', i);
    if (a === -1) { out += tpl.slice(i); break; }
    const b = tpl.indexOf('}', a + 1);
    if (b === -1) { out += tpl.slice(i); break; }
    const name = tpl.slice(a + 1, b);
    if (Object.prototype.hasOwnProperty.call(params, name)) out += tpl.slice(i, a) + String(params[name] == null ? '' : params[name]);
    else out += tpl.slice(i, b + 1);
    i = b + 1;
  }
  return out;
}
function paren(x) { return t('paren', { x: x }); }
function applyI18n() {
  document.documentElement.lang = LANG;
  document.title = t('dashTitle');
  for (const el of document.querySelectorAll('[data-i18n]')) el.textContent = t(el.getAttribute('data-i18n'));
  for (const el of document.querySelectorAll('[data-i18n-title]')) el.title = t(el.getAttribute('data-i18n-title'));
  const sel = document.getElementById('lang-select');
  if (sel && document.activeElement !== sel) {
    const pref = langPref();
    sel.textContent = '';
    const auto = document.createElement('option');
    auto.value = 'auto';
    auto.textContent = t('langAuto', { name: I18N.names[resolveLang('auto', navigator.language || '')] });
    sel.appendChild(auto);
    for (const id of Object.keys(I18N.locales)) {
      const o = document.createElement('option');
      o.value = id; o.textContent = I18N.names[id] || id;
      sel.appendChild(o);
    }
    sel.value = I18N.locales[pref] ? pref : 'auto';
  }
}

function keyOf(f) { return f.identity || ((f.rule || '') + ' ' + (f.target || '') + ':' + (f.line == null ? '?' : f.line)); }
const readSet = LS.get('vgd.read', {});
const openState = LS.get('vgd.open', {});
function persistDetails(det, key, defaultOpen) {
  if (key in openState) det.open = !!openState[key];
  else det.open = !!defaultOpen;
  det.addEventListener('toggle', () => { openState[key] = det.open; LS.set('vgd.open', openState); });
}
function updateUnread() {
  let n = 0;
  for (const agents of Object.values(DATA.groups || {})) {
    for (const fs2 of Object.values(agents || {})) for (const f of fs2) if (!readSet[keyOf(f)]) n += 1;
  }
  document.getElementById('unread').textContent = n > 0 ? t('unread', { n: n }) : '';
}
function markRead(k, badge) {
  if (!readSet[k]) { readSet[k] = true; LS.set('vgd.read', readSet); }
  if (badge) badge.remove();
  updateUnread();
}
function setStatus(msg) { document.getElementById('status').textContent = msg; }

// ── API（同源 fetch；token 掛 query）──
async function api(kind, extra) {
  const res = await fetch('/api/action?token=' + encodeURIComponent(TOKEN), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(Object.assign({ kind }, extra || {})),
  });
  return res.json();
}
function findingRef(f) { return { rule: f.rule, target: f.target, line: f.line }; }
// worker 的回覆若帶 noteKey 就用本頁語言翻，否則用它給的 note 文字
function noteOf(r) {
  if (r && r.noteKey) return t(r.noteKey, r.noteParams || {});
  return r && r.note ? r.note : '';
}
function report(r, okMsg) {
  if (r && r.ok) { const n = noteOf(r); setStatus(okMsg + (n ? paren(n) : '')); return; }
  const n = noteOf(r);
  setStatus(t('dashFailed', { reason: n || ((r && (r.reason || r.error)) || t('unknownError')) }));
}

// ── 渲染 ──
function mkBtn(label, title, onClick) {
  const b = document.createElement('button');
  b.className = 'btn'; b.type = 'button'; b.textContent = label;
  if (title) b.title = title;
  b.addEventListener('click', async () => { b.disabled = true; try { await onClick(); } finally { b.disabled = false; } });
  return b;
}

function findingRow(f) {
  const row = document.createElement('div');
  row.className = 'row ' + (f.severity || 'medium');
  const titleLine = document.createElement('div');
  titleLine.className = 'title';
  const title = document.createElement('span');
  const k = keyOf(f);
  let badge = null;
  if (!readSet[k]) {
    badge = document.createElement('span');
    badge.className = 'badge-new';
    badge.textContent = t('badgeNew');
    title.appendChild(badge);
  }
  title.appendChild(document.createTextNode(f.title || f.rule));
  titleLine.appendChild(title);
  row.addEventListener('click', () => markRead(k, badge));

  const shortTitle = f.title || f.rule;
  const btns = document.createElement('span');
  btns.className = 'btns';
  btns.appendChild(mkBtn(t('btnOpen'), t('dashBtnOpenTitle'), async () => {
    report(await api('open', findingRef(f)), t('dashOpened', { path: f.target || '' }));
  }));
  btns.appendChild(mkBtn(t('btnFix'), t('dashBtnFixTitle'), async () => {
    report(await api('fix', findingRef(f)), t('dashFixSent', { title: shortTitle }));
  }));
  btns.appendChild(mkBtn(t('btnIssue'), t('dashBtnIssueTitle'), async () => {
    report(await api('issue', findingRef(f)), t('dashIssueSent', { title: shortTitle }));
  }));
  btns.appendChild(mkBtn(t('btnIgnoreFile'), t('dashBtnIgnoreFileTitle'), async () => {
    report(await api('ignore', findingRef(f)), t('dashIgnored'));
  }));
  btns.appendChild(mkBtn(t('btnDismiss'), t('dashBtnDismissTitle'), async () => {
    report(await api('dismiss', findingRef(f)), t('dashDismissed'));
  }));
  titleLine.appendChild(btns);
  row.appendChild(titleLine);

  if (f.description) {
    const desc = document.createElement('div');
    desc.className = 'desc';
    desc.textContent = f.description;
    row.appendChild(desc);
  }
  if (Array.isArray(f.snippet) && f.snippet.length) {
    const pre = document.createElement('pre');
    pre.className = 'snippet';
    const rows = [];
    for (const s2 of f.snippet.slice(0, 7)) {
      const mark = s2.ln === f.line ? '▸ ' : '  ';
      rows.push(mark + String(s2.ln) + '  ' + String(s2.text == null ? '' : s2.text).slice(0, 200));
    }
    pre.textContent = rows.join('\\n');
    row.appendChild(pre);
  }
  const loc = document.createElement('div');
  loc.className = 'loc';
  const conf = typeof f.confidence === 'number' ? ' · ' + Math.round(f.confidence * 100) + '%' : '';
  const when = f.foundAt ? new Date(f.foundAt).toLocaleTimeString() + ' · ' : '';
  const agent = f.agent && f.agent !== 'unknown' ? ' · ' + f.agent : '';
  loc.textContent = when + (f.target || '?') + ':' + (f.line == null ? '?' : f.line) + ' · ' + (f.layer || '') + conf + agent;
  row.appendChild(loc);
  const issue = DATA.issues && DATA.issues[(f.rule || '') + ' ' + (f.target || '')];
  if (issue) {
    const b2 = document.createElement('div');
    b2.className = 'loc';
    b2.textContent = issue.state === 'CLOSED' ? t('issueClosed', { n: issue.number }) : t('issueOpen', { n: issue.number });
    row.appendChild(b2);
  }
  return row;
}

function splitBySeverity(groups) {
  const serious = {}; const normal = {};
  for (const [wt, agents] of Object.entries(groups || {})) {
    for (const [agent, fs2] of Object.entries(agents || {})) {
      for (const f of fs2) {
        const bucket = SERIOUS.includes(f.severity) ? serious : normal;
        (bucket[wt] = bucket[wt] || {})[agent] = (bucket[wt][agent] || []).concat(f);
      }
    }
  }
  return { serious, normal };
}
function countOf(groups) {
  let n = 0;
  for (const agents of Object.values(groups)) for (const fs2 of Object.values(agents)) n += fs2.length;
  return n;
}
function renderSection(parent, title, cls, groups, defaultOpen) {
  const wts = Object.entries(groups || {});
  let total = 0;
  for (const [, agents] of wts) for (const fs2 of Object.values(agents)) total += fs2.length;
  if (!total) return 0;
  const h = document.createElement('div');
  h.className = 'sec ' + cls;
  h.textContent = title + paren(total);
  parent.appendChild(h);
  for (const [wt, agents] of wts) {
    const all = [];
    for (const fs2 of Object.values(agents || {})) all.push(...fs2);
    if (!all.length) continue;
    const det = document.createElement('details');
    persistDetails(det, cls + '|' + wt, defaultOpen);
    const sum = document.createElement('summary');
    sum.textContent = wt.split('::').pop() + paren(all.length);
    det.appendChild(sum);
    for (const f of all) det.appendChild(findingRow(f));
    parent.appendChild(det);
  }
  return total;
}

function scanBadge(s) {
  const sev = s.sev;
  if (!sev) return { icon: (s.count > 0 ? '🔴' : '✅'), text: '' };
  const ser = (sev.critical || 0) + (sev.high || 0);
  const nrm = sev.medium || 0;
  const lw = sev.low || 0;
  const ps = [];
  if (ser) ps.push(t('sevSerious', { n: ser }));
  if (nrm) ps.push(t('sevNormal', { n: nrm }));
  if (lw) ps.push(t('sevLow', { n: lw }));
  return { icon: ser ? '🔴' : (nrm ? '🟠' : (lw ? '🟡' : '✅')), text: ps.join(' · ') };
}
function scanNote(s, fallbackKey) {
  if (s.noteKey) return t(s.noteKey, s.noteParams || {});
  return s.note || t(fallbackKey);
}

function render() {
  const scrollY = window.scrollY;
  applyI18n();
  const el = document.getElementById('main');
  el.textContent = '';
  let total = 0;
  for (const agents of Object.values(DATA.groups || {})) for (const fs2 of Object.values(agents)) total += fs2.length;
  const { serious, normal } = splitBySeverity(DATA.groups);

  const box = document.getElementById('summary');
  box.textContent = '';
  function kpi(n, label, cls) {
    const tile = document.createElement('div');
    tile.className = 'kpi ' + cls + (n === 0 ? ' zero' : '');
    const num = document.createElement('div'); num.className = 'n'; num.textContent = String(n);
    const lab = document.createElement('div'); lab.className = 'l'; lab.textContent = label;
    tile.appendChild(num); tile.appendChild(lab); box.appendChild(tile);
  }
  kpi(countOf(serious), t('serious'), 'crit');
  kpi(countOf(normal), t('normal'), 'warn');
  kpi((DATA.resolved || []).length, t('resolved'), 'ok');
  const scans = DATA.scans || [];
  const watchState = new Map();
  let lastScanAt = null;
  for (const sc of scans) {
    if (sc && sc.path && !watchState.has(sc.path)) watchState.set(sc.path, sc.kind);
    if (!lastScanAt && sc && sc.kind === 'scan' && sc.time) lastScanAt = sc.time;
  }
  let watching = 0;
  for (const kind of watchState.values()) if (kind === 'watch') watching += 1;
  const scanTxt = lastScanAt ? new Date(lastScanAt).toLocaleTimeString() : t('noScanYet');
  document.getElementById('meta').textContent = t('watchMeta', { n: watching, time: scanTxt });

  document.getElementById('empty-state').hidden = total > 0;
  if (total) {
    const sWrap = document.createElement('div');
    sWrap.id = 'sec-serious';
    renderSection(sWrap, t('serious'), 'serious', serious, true);
    const nWrap = document.createElement('div');
    nWrap.id = 'sec-normal';
    renderSection(nWrap, t('normal'), 'normal', normal, true);
    el.appendChild(sWrap); el.appendChild(nWrap);
    applyFilter();
  }

  // 已修正
  const rEl = document.getElementById('resolved');
  rEl.textContent = '';
  const rl = DATA.resolved || [];
  if (rl.length) {
    const det = document.createElement('details');
    persistDetails(det, 'resolved', false);
    const sum = document.createElement('summary');
    sum.textContent = t('resolvedTitle') + paren(rl.length);
    det.appendChild(sum);
    for (const f of rl.slice(0, 20)) {
      const row = document.createElement('div');
      row.className = 'row low';
      const tt = document.createElement('div'); tt.textContent = f.title || f.rule; row.appendChild(tt);
      const loc = document.createElement('div');
      loc.className = 'loc';
      loc.textContent = (f.resolvedAt ? t('resolvedAtPrefix', { time: new Date(f.resolvedAt).toLocaleTimeString() }) : '') + (f.target || '?') + ':' + (f.line == null ? '?' : f.line);
      row.appendChild(loc);
      det.appendChild(row);
    }
    rEl.appendChild(det);
  }

  // 掃描記錄
  const sEl = document.getElementById('scanlog');
  sEl.textContent = '';
  if (scans.length) {
    const det = document.createElement('details');
    persistDetails(det, 'scanlog', false);
    const sum = document.createElement('summary');
    sum.textContent = t('scanLogTitle') + paren(scans.length);
    det.appendChild(sum);
    for (const sc of scans.slice(0, 15)) {
      const row = document.createElement('div');
      row.className = 'scan';
      const time = sc.time ? new Date(sc.time).toLocaleTimeString() : '?';
      let desc;
      if (sc.kind === 'watch') desc = t('scanWatch', { note: scanNote(sc, 'noteWatch'), path: sc.path || '' });
      else if (sc.kind === 'unwatch') desc = t('scanUnwatch', { note: scanNote(sc, 'noteUnwatch'), path: sc.path || sc.worktreeId || '' });
      else if (sc.kind === 'skip') desc = t('scanSkip', { note: scanNote(sc, 'noteSkip'), path: sc.path || '' });
      else if (sc.error) desc = t('scanFailed', { path: sc.path || '?', error: sc.error });
      else {
        const b = scanBadge(sc);
        desc = t('scanResult', { icon: b.icon, path: sc.path || '?', n: sc.count || 0, detail: b.text ? paren(b.text) : '', layers: (sc.layers || []).join('+'), ms: sc.elapsedMs == null ? '?' : sc.elapsedMs })
          + (sc.llmError ? '\\n    ' + t('llmErrorLine', { error: String(sc.llmError).slice(0, 200) }) : '');
      }
      if (sc.llmError) row.style.whiteSpace = 'pre-line';
      row.textContent = time + ' ' + desc;
      det.appendChild(row);
    }
    sEl.appendChild(det);
  }

  syncSettings();
  updateUnread();
  window.scrollTo(0, scrollY);
}

// ── severity 過濾 ──
let filter = 'all';
function applyFilter() {
  const s = document.getElementById('sec-serious');
  const n = document.getElementById('sec-normal');
  if (s) s.style.display = (filter === 'normal') ? 'none' : '';
  if (n) n.style.display = (filter === 'serious') ? 'none' : '';
}
document.getElementById('chips').addEventListener('click', (ev) => {
  const chip = ev.target.closest('.chip');
  if (!chip || !chip.dataset.f) return;
  for (const c of document.querySelectorAll('.chip[data-f]')) c.classList.toggle('active', c === chip);
  filter = chip.dataset.f;
  applyFilter();
});
document.getElementById('mark-all-read').addEventListener('click', () => {
  for (const agents of Object.values(DATA.groups || {})) {
    for (const fs2 of Object.values(agents || {})) for (const f of fs2) readSet[keyOf(f)] = true;
  }
  LS.set('vgd.read', readSet);
  for (const b of document.querySelectorAll('.badge-new')) b.remove();
  updateUnread();
});

// ── 設定同步（渲染時帶入現值；操作時 POST action）──
let settingsBound = false;
function syncSettings() {
  const st = DATA.settings || {};
  const master = document.getElementById('notify-toggle');
  if (document.activeElement !== master) master.checked = st.notify !== false;
  const fw = document.getElementById('llm-framework');
  const model = document.getElementById('llm-model');
  function modelsFor(fwName) {
    const lists = {
      claude: [['', t('modelDefaultLabel', { model: 'haiku' })], ['haiku', 'haiku'], ['sonnet', 'sonnet'], ['opus', 'opus']],
      codex: [['', t('cliDefault')], ['gpt-5-codex', 'gpt-5-codex'], ['gpt-5', 'gpt-5'], ['codex-mini-latest', 'codex-mini-latest']],
      gemini: [['', t('cliDefault')], ['gemini-2.5-flash', 'gemini-2.5-flash'], ['gemini-2.5-pro', 'gemini-2.5-pro']],
    };
    return lists[fwName] || [['', t('cliDefault')]];
  }
  const llm = st.llm || {};
  function rebuild(selected) {
    model.textContent = '';
    for (const [val, label] of modelsFor(fw.value)) {
      const o = document.createElement('option');
      o.value = val; o.textContent = label;
      model.appendChild(o);
    }
    model.value = selected || '';
    if (model.value !== (selected || '')) model.value = '';
  }
  if (document.activeElement !== fw && document.activeElement !== model) {
    fw.value = llm.framework || 'claude';
    rebuild(llm.model || '');
  }
  if (!settingsBound) {
    settingsBound = true;
    master.addEventListener('change', async () => {
      report(await api('notify', { value: master.checked ? 'on' : 'off' }), t('dashNotifyUpdated'));
    });
    const persistLlm = async () => {
      report(await api('llm', { framework: fw.value, model: model.value }), t('dashLlmSwitched', { fw: fw.value, model: model.value ? ' / ' + model.value : t('modelDefaultParen') }));
    };
    fw.addEventListener('change', () => { rebuild(''); persistLlm(); });
    model.addEventListener('change', persistLlm);
    const sel = document.getElementById('lang-select');
    sel.addEventListener('change', async () => {
      const v = sel.value;
      LS.set('vgd.lang', v);
      LANG = resolveLang(v, navigator.language || '');
      render();
      report(await api('locale', { value: v }), t('langChanged', { name: I18N.names[LANG] }));
    });
  }
}
persistDetails(document.getElementById('settings-card'), 'settings', false);

// ── 輪詢（真即時的核心）：2 秒一次，資料變了才重繪 ──
const dot = document.getElementById('live-dot');
let failStreak = 0;
async function tick() {
  try {
    const res = await fetch('/api/state?token=' + encodeURIComponent(TOKEN), { cache: 'no-store' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const text = await res.text();
    failStreak = 0;
    dot.className = 'dot live';
    if (text !== lastJson) {
      lastJson = text;
      DATA = JSON.parse(text);
      // worker 端語言偏好只在使用者沒在本頁明確選過時才跟
      if (!LS.get('vgd.lang', null)) LANG = resolveLang(langPref(), navigator.language || '');
      render();
      setStatus(t('dashUpdated', { time: new Date().toLocaleTimeString() }));
    }
  } catch (e) {
    failStreak += 1;
    if (failStreak >= 3) {
      dot.className = 'dot dead';
      setStatus(t('dashDisconnected'));
    }
  }
}
applyI18n();
tick();
setInterval(tick, 2000);
</script>
</body>
</html>
`;
