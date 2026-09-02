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
