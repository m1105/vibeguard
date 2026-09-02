import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { startPanelServer, PANEL_PORT_RANGE } from '../panel-server.mjs';

const GROUPED = {
  wt1: {
    claude: [
      { rule: 'hardcoded_secret_aws_access_key', severity: 'critical', target: '/repo/a.js', line: 3 },
    ],
  },
};

const TOKEN = 'test-token-1234';

const servers = [];
async function start(deps) {
  // 不重用 port：undici 連線池會對「close 後同 port 重開」重用死 socket（fetch failed）
  const s = await startPanelServer({ token: TOKEN, ...deps });
  servers.push(s);
  return s;
}
const base = { getGroupedFindings: () => ({}), openFile: async () => {}, fixFinding: async () => ({ ok: true }) };
after(async () => { for (const s of servers) await s.close().catch(() => {}); });

test('無 token / 錯 token 一律 403（每個請求都要驗）', async () => {
  const calls = [];
  const server = await start({ ...base, openFile: async () => { calls.push('open'); } });
  assert.equal((await fetch(`${server.url}/findings`)).status, 403);
  assert.equal((await fetch(`${server.url}/findings?token=wrong`)).status, 403);
  const r = await fetch(`${server.url}/open?token=wrong`, { method: 'POST', body: '{}' });
  assert.equal(r.status, 403);
  assert.deepEqual(calls, [], '被拒的請求不得觸發任何動作');
});

test('startPanelServer 不給 token 直接拒啟（不允許無防護的 server）', async () => {
  await assert.rejects(() => startPanelServer({ ...base }), /token/);
});

test('跨域 Origin 一律 403（防網頁 CSRF）；同源 Origin 放行（dashboard 自己的 POST 會帶）', async () => {
  const server = await start(base);
  const cross = await fetch(`${server.url}/findings?token=${TOKEN}`, { headers: { Origin: 'https://evil.example' } });
  assert.equal(cross.status, 403);
  const same = await fetch(`${server.url}/findings?token=${TOKEN}`, { headers: { Origin: server.url } });
  assert.equal(same.status, 200);
});

test('Host 頭不對 → 403（防 DNS rebinding）', async () => {
  // fetch 禁改 Host 頭（forbidden header），用原生 http 模擬 rebinding 請求
  const { request } = await import('node:http');
  const server = await start(base);
  const status = await new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: server.port, path: `/findings?token=${TOKEN}`, headers: { Host: 'evil.example:80' } },
      (res) => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
    req.end();
  });
  assert.equal(status, 403);
});

test('GET / 回 dashboard HTML（no-store，不快取）', async () => {
  const server = await start({ ...base, dashboardHtml: () => '<!doctype html><title>VG</title>' });
  const res = await fetch(`${server.url}/?token=${TOKEN}`);
  assert.equal(res.status, 200);
  assert.ok((res.headers.get('content-type') || '').includes('text/html'));
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.ok((await res.text()).includes('VG'));
});

test('GET /api/state 回 getState 的完整狀態', async () => {
  const server = await start({ ...base, getState: () => ({ generatedAt: 't1', groups: GROUPED }) });
  const res = await fetch(`${server.url}/api/state?token=${TOKEN}`);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.generatedAt, 't1');
  assert.deepEqual(data.groups, GROUPED);
});

test('POST /api/action 轉交 doAction 並回其結果', async () => {
  const seen = [];
  const server = await start({ ...base, doAction: async (b) => { seen.push(b); return { ok: true, did: b.kind }; } });
  const res = await fetch(`${server.url}/api/action?token=${TOKEN}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'open', key: 'k1' }),
  });
  assert.deepEqual(await res.json(), { ok: true, did: 'open' });
  assert.deepEqual(seen, [{ kind: 'open', key: 'k1' }]);
});

test('GET /findings 回注入的分組資料（無 CORS 頭，跨域頁面讀不到）', async () => {
  const server = await start({ ...base, getGroupedFindings: () => GROUPED });
  assert.equal(PANEL_PORT_RANGE[0], 47391);
  const res = await fetch(`${server.url}/findings?token=${TOKEN}`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), GROUPED);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('POST /open → openFile 被叫到、參數正確', async () => {
  const seen = [];
  const server = await start({ ...base, openFile: async (path, wt) => { seen.push([path, wt]); } });
  const res = await fetch(`${server.url}/open?token=${TOKEN}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: '/repo/a.js', worktreeId: 'wt1' }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true });
  assert.deepEqual(seen, [['/repo/a.js', 'wt1']]);
});

test('POST /fix → fixFinding 被叫到並回傳其結果', async () => {
  const seen = [];
  const server = await start({ ...base, fixFinding: async (f) => { seen.push(f); return { ok: true, fixed: f.rule }; } });
  const res = await fetch(`${server.url}/fix?token=${TOKEN}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule: 'x', line: 9 }),
  });
  assert.deepEqual(await res.json(), { ok: true, fixed: 'x' });
  assert.deepEqual(seen, [{ rule: 'x', line: 9 }]);
});

test('未知路徑 → 404；OPTIONS 204 且不發 CORS 標頭', async () => {
  const server = await start(base);
  assert.equal((await fetch(`${server.url}/nope?token=${TOKEN}`)).status, 404);
  const pre = await fetch(`${server.url}/findings`, { method: 'OPTIONS' });
  assert.equal(pre.status, 204);
  assert.equal(pre.headers.get('access-control-allow-methods'), null);
});

test('openFile 拋錯 → 500 {ok:false}', async () => {
  const server = await start({ ...base, openFile: async () => { throw new Error('spawn failed'); } });
  const res = await fetch(`${server.url}/open?token=${TOKEN}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: '/x' }),
  });
  assert.equal(res.status, 500);
  const body = await res.json();
  assert.equal(body.ok, false);
  assert.ok(body.error.includes('spawn failed'));
});

test('close 後 port 釋放（連線被拒）', async () => {
  const s = await start(base);
  const url = s.url;
  await s.close();
  await assert.rejects(() => fetch(url + `/findings?token=${TOKEN}`));
});
