import { test } from 'node:test';
import assert from 'node:assert/strict';
import { auditSemantics } from '../shield/l3-local.mjs';

// JS 端點 regex 需要 handler 以「換行 + }」收尾（[\s\S]{0,1800}?\n\s*}）
const JS_ADMIN = `app.post('/admin/reset', (req, res) => {
  const u = req.body.user;
  db.query('UPDATE users SET password = ?', [u]);
})`;

const JS_ADMIN_SAFE = `app.post('/admin/reset', authenticate, (req, res) => {
  const u = validate(req.body.user);
  try { db.query('UPDATE users SET password = ?', [u]); } catch (e) { res.status(500); }
  ratelimit(req);
})`;

const JS_LOGIN = `app.post('/login', (req, res) => {
  const u = req.body.user;
})`;

const JS_PUBLIC_GET = `app.get('/public/news', (req, res) => {
  res.json(news)
})`;

const PY_USER_DELETE = `@app.route('/user/delete', methods=['POST'])
def delete_user():
    u = request.form['id']
    return 'ok'`;

// --- JS 端點 ---

test('JS: /admin/reset 無防護 → auth(high) + rate(medium) + input(medium) + error(low)', () => {
  const out = auditSemantics(JS_ADMIN, { target: 't', language: 'javascript' });
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes('l3_missing_authentication'));
  assert.ok(rules.includes('l3_missing_rate_limiting')); // post ≠ get 且無限流字樣
  assert.ok(rules.includes('l3_missing_input_validation'));
  assert.ok(rules.includes('l3_missing_error_handling')); // 有 input + db.query IO + 無 try
  const auth = out.find((f) => f.rule === 'l3_missing_authentication');
  assert.equal(auth.severity, 'high');
  assert.ok(auth.description.includes('POST /admin/reset'));
});

test('JS: 有 authenticate+validate+try+ratelimit → 全不報', () => {
  assert.deepEqual(auditSemantics(JS_ADMIN_SAFE, { target: 't', language: 'javascript' }), []);
});

test('JS: /login 無限流字樣 → missing_rate_limiting', () => {
  const out = auditSemantics(JS_LOGIN, { target: 't', language: 'javascript' });
  assert.ok(out.some((f) => f.rule === 'l3_missing_rate_limiting'));
});

test('JS: GET /public/news（非敏感、無 input）→ 全不報', () => {
  assert.deepEqual(auditSemantics(JS_PUBLIC_GET, { target: 't', language: 'javascript' }), []);
});

// --- Python 端點 ---

test('PY: @app.route /user/delete + request.form → auth + rate + input（無 IO 所以無 error）', () => {
  const out = auditSemantics(PY_USER_DELETE, { target: 't', language: 'python' });
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes('l3_missing_authentication')); // path 含 user
  assert.ok(rules.includes('l3_missing_rate_limiting')); // route 無 method group → 'request' ≠ get
  assert.ok(rules.includes('l3_missing_input_validation')); // request.form 無 validate
  assert.ok(!rules.includes('l3_missing_error_handling')); // 無 IO 關鍵字
});

test('PY: language=py 也走 python 規則', () => {
  const out = auditSemantics(PY_USER_DELETE, { target: 't', language: 'py' });
  assert.ok(out.length > 0);
});

// --- finding 形狀 ---

test('每筆 confidence=0.65、layer=L3、type=missing_security_measure、evidence 空', () => {
  const out = auditSemantics(JS_ADMIN, { target: 't', language: 'javascript' });
  assert.ok(out.length > 0);
  for (const f of out) {
    assert.equal(f.confidence, 0.65);
    assert.equal(f.layer, 'L3');
    assert.equal(f.type, 'missing_security_measure');
    assert.equal(f.evidence, '');
  }
});

test('line 用 match.index 定位', () => {
  const [f] = auditSemantics('const x = 1;\n' + JS_ADMIN, { target: 't', language: 'javascript' });
  assert.equal(f.line, 2);
  assert.equal(f.column, 1);
});

test('target 帶入 finding；無害文字 → 空', () => {
  const out = auditSemantics(JS_ADMIN, { target: 'src/routes.js', language: 'javascript' });
  assert.equal(out[0].target, 'src/routes.js');
  assert.deepEqual(auditSemantics('const x = 42;', { target: 't', language: 'javascript' }), []);
});
