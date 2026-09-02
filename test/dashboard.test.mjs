import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDashboardHtml } from '../dashboard.mjs';

test('dashboard: script 語法合法（template literal 反斜線教訓的正式驗收）', () => {
  const html = buildDashboardHtml();
  const i = html.indexOf('<script>') + '<script>'.length;
  const j = html.indexOf('</' + 'script>');
  assert.ok(i > 8 && j > i, '要有 script 區');
  assert.doesNotThrow(() => new Function(html.slice(i, j)));
});

test('dashboard: 即時輪詢 /api/state（2 秒、資料變才重繪）+ token 從 URL 取', () => {
  const html = buildDashboardHtml();
  assert.ok(html.includes('/api/state'), '輪詢端點');
  assert.ok(html.includes('setInterval(tick, 2000)'), '2 秒輪詢');
  assert.ok(html.includes('location.search'), 'token 從 URL query 取');
  assert.ok(html.includes('lastJson'), '資料沒變不重繪');
});

test('dashboard: 動作全走 POST /api/action（不再借道 terminal 打指令）', () => {
  const html = buildDashboardHtml();
  assert.ok(html.includes('/api/action'));
  for (const kind of ["'open'", "'fix'", "'issue'", "'ignore'", "'dismiss'", "'notify'", "'llm'"]) {
    assert.ok(html.includes('api(' + kind) || html.includes(kind), '要有 ' + kind + ' 動作');
  }
  assert.ok(!html.includes('terminal.sendText'), 'dashboard 不走 panel bridge');
});

test('dashboard: 自包含（無外部資源）+ 連線狀態指示', () => {
  const html = buildDashboardHtml();
  assert.ok(!html.includes('src="http'));
  assert.ok(!html.includes('href="http'));
  assert.ok(html.includes('live-dot'), '要有連線狀態點');
  assert.ok(html.includes('failStreak'), '連線失敗要有降級提示');
});

test('dashboard: 完整渲染（KPI/snippet/掃描記錄/已修正/未讀/設定）', () => {
  const html = buildDashboardHtml();
  for (const marker of ['嚴重', '注意', '已修正', 'f.snippet', '最近掃描記錄', 'badge-new', '全部已讀', '啟用通知', 'llm-framework', '最後掃描']) {
    assert.ok(html.includes(marker), '缺 ' + marker);
  }
  assert.ok(!html.includes('innerHTML ='), '一律 textContent 渲染');
});

// ── i18n（與 panel 同一份字典；dashboard 可 fetch，切語言直接 POST /api/action locale）──
import { LOCALES, LOCALE_NAMES } from '../i18n.mjs';

test('dashboard: i18n 字典整包內嵌（與 i18n.mjs 同一份）+ t() + 語言切換器', () => {
  const html = buildDashboardHtml();
  const start = html.indexOf('const I18N = ');
  assert.ok(start !== -1, '找不到 I18N 內嵌');
  const pack = JSON.parse(html.slice(start + 'const I18N = '.length, html.indexOf(';\n', start)));
  assert.deepEqual(Object.keys(pack.locales).sort(), Object.keys(LOCALES).sort());
  assert.deepEqual(pack.locales.en, LOCALES.en, '內嵌字典必須就是 i18n.mjs 的（單一真相）');
  assert.deepEqual(pack.names, LOCALE_NAMES);
  assert.ok(html.includes('function t('), '要有 t()');
  assert.ok(html.includes('id="lang-select"'), '要有語言切換器');
  assert.ok(html.includes('vgd.lang'), '語言偏好存 localStorage（vgd. 前綴與 panel 區隔）');
  assert.ok(html.includes('navigator.language'), 'auto 看瀏覽器語言');
  assert.ok(html.includes("api('locale'") || html.includes("'locale'"), '切語言要 POST locale 動作同步 worker');
  assert.ok(html.includes('settings.locale'), 'worker 端偏好作為次順位');
  assert.ok(html.includes('function applyI18n'), '靜態字串套用');
  assert.ok(html.includes("querySelectorAll('[data-i18n]')"));
  assert.ok(html.includes('documentElement.lang'));
});

test('dashboard: 靜態字串走 data-i18n；關鍵動態訊息走 t()', () => {
  const html = buildDashboardHtml();
  for (const key of ['dashSubtitle', 'chipAll', 'chipSerious', 'chipNormal', 'markAllRead', 'settings', 'dashSettingsHint', 'notifyToggle', 'llmPicker', 'langLabel', 'emptyTitle', 'dashEmptySub']) {
    assert.ok(html.includes(`data-i18n="${key}"`), `靜態字串 ${key} 要標 data-i18n`);
    assert.ok(LOCALES['zh-TW'][key], `字典要有 ${key}`);
  }
  const script = html.slice(html.indexOf('<' + 'script>'), html.indexOf('</' + 'script>'));
  for (const key of ['unread', 'dashFailed', 'unknownError', 'dashOpened', 'dashFixSent', 'dashIssueSent', 'dashIgnored', 'dashDismissed',
    'serious', 'normal', 'resolved', 'noScanYet', 'watchMeta', 'resolvedTitle', 'scanLogTitle', 'scanFailed', 'scanResult',
    'dashNotifyUpdated', 'dashLlmSwitched', 'dashUpdated', 'dashDisconnected', 'issueClosed', 'issueOpen', 'btnOpen', 'btnFix', 'btnIssue', 'btnIgnoreFile', 'btnDismiss', 'langChanged']) {
    assert.ok(script.includes(`t('${key}'`), `訊息 ${key} 要走 t()`);
    assert.ok(LOCALES['zh-TW'][key], `字典要有 ${key}`);
  }
  assert.ok(html.includes('noteKey'), '掃描記錄 note 優先用 noteKey 翻譯');
});
