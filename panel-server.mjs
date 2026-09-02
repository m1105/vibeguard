// panel-server.mjs — 127.0.0.1 HTTP server（即時 dashboard 通道）。
//
// panel 沙箱 CSP `connect-src 'none'` 不能 fetch（docs/01 §10），但 Orca 內嵌瀏覽器
// （`orca goto --url`）沒有這個限制：dashboard 頁由本 server 供應，前端每 2 秒輪詢
// /api/state → 真即時、不重刷頁面。panel 保留為快照入口。
//
// 安全模型（本地 server 四重防線；歷史教訓見 CLAUDE.md dogfooding #4）：
//   1. 只綁 127.0.0.1
//   2. 每個請求都要 token（?token= 或 x-vibeguard-token 頭）——worker 啟動時隨機產生，
//      timingSafeEqual 比對；worker 重啟 token 就換（舊 dashboard 分頁自然失效）
//   3. Host 必須是 127.0.0.1:<port>（防 DNS rebinding）；Origin 若存在必須同源（防 CSRF）
//   4. 不發任何 CORS 頭（跨域頁面讀不到回應）

import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';

export const PANEL_PORT_RANGE = [47391, 47420]; // 從 47391 起找空閒 port

const BODY_LIMIT = 64 * 1024;

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}

function sendHtml(res, html) {
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(html);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > BODY_LIMIT) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return timingSafeEqual(ba, bb);
}

/**
 * @param {{ token: string,
 *   getState?: () => object|Promise<object>,
 *   doAction?: (body:object) => Promise<any>,
 *   dashboardHtml?: () => string,
 *   openFile: (path:string, worktreeId?:string) => Promise<any>,
 *   fixFinding: (finding:object) => Promise<any>,
 *   getGroupedFindings: () => object|Promise<object>, log?: Function }} deps
 * @returns {Promise<{ port:number, url:string, close:() => Promise<void> }>}
 */
export async function startPanelServer({ token, getState, doAction, dashboardHtml, openFile, fixFinding, getGroupedFindings, log = () => {} }) {
  if (!token) throw new Error('panel-server 需要 token（安全模型第 2 道防線）');
  let boundPort = 0;
  const server = http.createServer(async (req, res) => {
    try {
      const expectedHost = `127.0.0.1:${boundPort}`;
      // 防 DNS rebinding：Host 不對一律拒絕
      if ((req.headers.host ?? '') !== expectedHost) {
        sendJson(res, 403, { ok: false, error: 'bad host' });
        return;
      }
      // 防 CSRF：帶 Origin 的請求必須同源（dashboard 自己的 fetch/POST 會帶同源 Origin）
      const origin = req.headers.origin;
      if (origin && origin !== `http://${expectedHost}`) {
        sendJson(res, 403, { ok: false, error: 'cross-origin requests are not allowed' });
        return;
      }
      if (req.method === 'OPTIONS') {
        sendJson(res, 204, {});
        return;
      }
      const url = new URL(req.url ?? '/', `http://${expectedHost}`);
      const given = url.searchParams.get('token') ?? req.headers['x-vibeguard-token'] ?? '';
      if (!safeEqual(given, token)) {
        sendJson(res, 403, { ok: false, error: 'bad token' });
        return;
      }

      if (req.method === 'GET' && url.pathname === '/') {
        if (!dashboardHtml) { sendJson(res, 404, { ok: false, error: 'no dashboard' }); return; }
        sendHtml(res, dashboardHtml());
        return;
      }
      if (req.method === 'GET' && url.pathname === '/api/state') {
        sendJson(res, 200, (await getState?.()) ?? {});
        return;
      }
      if (req.method === 'POST' && url.pathname === '/api/action') {
        const body = JSON.parse(await readBody(req) || '{}');
        sendJson(res, 200, (await doAction?.(body)) ?? { ok: false, error: 'no action handler' });
        return;
      }
      // 舊 CLI/除錯路由（curl 加 ?token= 使用）
      if (req.method === 'GET' && url.pathname === '/findings') {
        sendJson(res, 200, (await getGroupedFindings()) ?? {});
        return;
      }
      if (req.method === 'POST' && url.pathname === '/open') {
        const body = JSON.parse(await readBody(req) || '{}');
        await openFile(body.path, body.worktreeId);
        sendJson(res, 200, { ok: true });
        return;
      }
      if (req.method === 'POST' && url.pathname === '/fix') {
        const finding = JSON.parse(await readBody(req) || '{}');
        sendJson(res, 200, (await fixFinding(finding)) ?? { ok: true });
        return;
      }
      sendJson(res, 404, { ok: false, error: 'not found' });
    } catch (err) {
      log(`panel-server 錯誤：${err?.message ?? err}`);
      if (!res.headersSent) sendJson(res, 500, { ok: false, error: String(err?.message ?? err) });
    }
  });

  // 從 PANEL_PORT_RANGE[0] 起找空閒 port
  const [lo, hi] = PANEL_PORT_RANGE;
  const port = await new Promise((resolve, reject) => {
    let p = lo;
    const tryListen = () => {
      const onErr = (err) => {
        if (err.code === 'EADDRINUSE' && p < hi) { p += 1; tryListen(); }
        else reject(err);
      };
      server.once('error', onErr);
      server.listen(p, '127.0.0.1', () => { server.removeListener('error', onErr); resolve(p); });
    };
    tryListen();
  });
  boundPort = port;

  return {
    port,
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}
