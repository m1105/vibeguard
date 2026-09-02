import { test } from 'node:test';
import assert from 'node:assert/strict';
import { CONFIG_RULES, AI_PATTERN_RULES, scanRules } from '../shield/l1-rules.mjs';

// --- 規則表結構 ---

test('rule table: 13 config + 20 ai_pattern = 33', () => {
  assert.equal(CONFIG_RULES.length, 13);
  assert.equal(AI_PATTERN_RULES.length, 20);
});

test('rule table: id 前綴 / type / g flag / 欄位齊全', () => {
  for (const r of CONFIG_RULES) {
    assert.ok(r.id.startsWith('insecure_config_'), r.id);
    assert.equal(r.type, 'insecure_config');
    assert.ok(r.regex.global, r.id);
    assert.ok(r.title && r.description && r.suggestion, r.id);
    assert.ok(Array.isArray(r.languages), r.id);
  }
  for (const r of AI_PATTERN_RULES) {
    assert.ok(r.id.startsWith('ai_pattern_'), r.id);
    assert.equal(r.type, 'ai_pattern_error');
    assert.ok(r.regex.global, r.id);
    assert.ok(r.title && r.description && r.suggestion, r.id);
  }
});

// --- 每條規則一個命中樣本（id → [樣本, language]） ---

const HITS = [
  // CONFIG（13）
  ['insecure_config_debug_true', 'DEBUG = True', 'python'],
  ['insecure_config_app_debug_true', 'app.debug = True', 'python'],
  ['insecure_config_allowed_hosts_wildcard', "ALLOWED_HOSTS = ['*']", 'python'],
  ['insecure_config_cors_allow_all', 'CORS_ALLOW_ALL = True', 'python'],
  ['insecure_config_acao_wildcard', "Access-Control-Allow-Origin: '*'", 'python'],
  ['insecure_config_disable_host_check', 'DANGEROUSLY_DISABLE_HOST_CHECK = true', 'javascript'],
  ['insecure_config_csrf_exempt', '@csrf_exempt\ndef view(request): pass', 'python'],
  ['insecure_config_spring_permit_all', '.requestMatchers("/api/**").permitAll()', 'java'],
  ['insecure_config_cross_origin_wildcard', '@CrossOrigin(origins = "*")', 'java'],
  ['insecure_config_eval', 'eval(userInput)', 'javascript'],
  ['insecure_config_python_exec', 'exec(user_code)', 'python'],
  ['insecure_config_pickle_loads', 'data = pickle.loads(payload)', 'python'],
  ['insecure_config_yaml_load_without_loader', 'cfg = yaml.load(stream)', 'python'],
  // AI_PATTERN（20）
  ['ai_pattern_default_password', 'password = "123456"', 'python'],
  ['ai_pattern_admin_admin_credentials', 'username = "admin"\npassword = "admin"', 'python'],
  ['ai_pattern_hardcoded_jwt_secret', 'JWT_SECRET = "mysupersecretvalue123"', 'javascript'],
  ['ai_pattern_sql_f_string', 'q = f"SELECT * FROM users WHERE id = {uid}"', 'python'],
  ['ai_pattern_dangerously_set_inner_html', 'dangerouslySetInnerHTML={{__html: userHtml}}', 'jsx'],
  ['ai_pattern_frontend_secret_name', 'VITE_API_SECRET = "abcdefgh12345"', 'javascript'],
  ['ai_pattern_jwt_none_algorithm', "jwt.sign(payload, secret, { algorithm: 'none' })", 'javascript'],
  ['ai_pattern_jwt_ignore_expiration', 'jwt.verify(token, secret, { ignoreExpiration: true })', 'javascript'],
  ['ai_pattern_tls_verification_disabled', "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'", 'javascript'],
  ['ai_pattern_requests_verify_false', 'requests.get(url, verify=False)', 'python'],
  ['ai_pattern_bcrypt_low_rounds', 'bcrypt.hash(password, 4)', 'javascript'],
  ['ai_pattern_math_random_token', 'const token = Math.random()', 'javascript'],
  ['ai_pattern_flask_secret_key_placeholder', 'SECRET_KEY = "secret"', 'python'],
  ['ai_pattern_fastapi_cors_credentials_wildcard', 'app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)', 'python'],
  ['ai_pattern_cookie_secure_false', 'res.cookie("session", v, { secure: false })', 'javascript'],
  ['ai_pattern_cookie_httponly_false', 'res.cookie("session", v, { httpOnly: false })', 'javascript'],
  ['ai_pattern_spring_csrf_disabled', 'http.csrf().disable()', 'java'],
  ['ai_pattern_jinja_autoescape_disabled', 'Environment(loader=loader, autoescape=False)', 'python'],
  ['ai_pattern_paramiko_auto_add_host_key', 'client.set_missing_host_key_policy(paramiko.AutoAddPolicy())', 'python'],
  ['ai_pattern_object_storage_public_write_acl', 'ACL = "public-read-write"', 'python'],
];

for (const [id, snippet, language] of HITS) {
  test(`hit: ${id}`, () => {
    const out = scanRules(snippet, { target: 't', language });
    const hit = out.find((f) => f.rule === id);
    assert.ok(hit, `expected ${id} to fire on: ${snippet}`);
    assert.equal(hit.layer, 'L1');
    assert.ok(hit.line >= 1);
  });
}

// --- severity / type 抽樣核對（逐字照 DeepSec） ---

test('severity: critical 規則抽樣', () => {
  const crit = ['ai_pattern_default_password', 'ai_pattern_admin_admin_credentials', 'ai_pattern_hardcoded_jwt_secret', 'ai_pattern_frontend_secret_name', 'ai_pattern_jwt_none_algorithm', 'ai_pattern_flask_secret_key_placeholder', 'ai_pattern_object_storage_public_write_acl'];
  for (const id of crit) {
    const r = AI_PATTERN_RULES.find((x) => x.id === id);
    assert.equal(r.severity, 'critical', id);
  }
});

test('severity: config 抽樣（acao=medium、spring_permit_all=medium、其餘多為 high）', () => {
  const sev = Object.fromEntries(CONFIG_RULES.map((r) => [r.id, r.severity]));
  assert.equal(sev['insecure_config_debug_true'], 'high');
  assert.equal(sev['insecure_config_acao_wildcard'], 'medium');
  assert.equal(sev['insecure_config_spring_permit_all'], 'medium');
  assert.equal(sev['insecure_config_yaml_load_without_loader'], 'high');
});

test('type: config → insecure_config，ai → ai_pattern_error', () => {
  const [f1] = scanRules('DEBUG = True', { target: 't', language: 'python' });
  assert.equal(f1.type, 'insecure_config');
  const [f2] = scanRules('password = "admin"', { target: 't', language: 'python' });
  assert.equal(f2.type, 'ai_pattern_error');
});

// --- 語言 gating ---

test('language gating: DEBUG=True 在 javascript 不報、python 才報', () => {
  assert.deepEqual(scanRules('DEBUG = True', { target: 't', language: 'javascript' }), []);
  assert.equal(scanRules('DEBUG = True', { target: 't', language: 'python' }).length, 1);
});

test('language gating: eval 任何語言都報（languages 空）', () => {
  assert.ok(scanRules('eval(x)', { target: 't', language: 'go' }).some((f) => f.rule === 'insecure_config_eval'));
});

test('language gating: exec( 只報 python', () => {
  assert.deepEqual(scanRules('exec(code)', { target: 't', language: 'javascript' }), []);
  assert.ok(scanRules('exec(code)', { target: 't', language: 'python' }).some((f) => f.rule === 'insecure_config_python_exec'));
});

test('language gating: 缺省 language 只跑全語言規則', () => {
  // DEBUG=True 是 python 限定，沒給 language 不該報
  assert.deepEqual(scanRules('DEBUG = True', { target: 't' }), []);
});

// --- 負向案例（防誤報，照 DeepSec 設計意圖） ---

test('negative: JWT_SECRET = process.env.JWT_SECRET 不報（負向前瞻）', () => {
  assert.deepEqual(scanRules('JWT_SECRET = process.env.JWT_SECRET', { target: 't', language: 'javascript' }), []);
});

test('negative: regex.exec( 不觸發 python_exec（lookbehind 擋 .exec）', () => {
  const out = scanRules('const m = pattern.exec(input)', { target: 't', language: 'python' });
  assert.equal(out.filter((f) => f.rule === 'insecure_config_python_exec').length, 0);
});

test('negative: dangerouslySetInnerHTML + DOMPurify（無空格）不報', () => {
  // 注意：DeepSec 原 regex 的負向前瞻只在冒號後「無空格」時生效；
  // `__html: DOMPurify...`（有空格）因 \s* 回溯照樣命中——Python 實測相同，屬原作行為，保持忠實。
  const out = scanRules('dangerouslySetInnerHTML={{__html:DOMPurify.sanitize(x)}}', { target: 't', language: 'jsx' });
  assert.equal(out.filter((f) => f.rule === 'ai_pattern_dangerously_set_inner_html').length, 0);
});

test('fidelity quirk: __html: DOMPurify（有空格）仍命中（與 DeepSec Python 行為一致）', () => {
  const out = scanRules('dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(x)}}', { target: 't', language: 'jsx' });
  assert.equal(out.filter((f) => f.rule === 'ai_pattern_dangerously_set_inner_html').length, 1);
});

test('negative: yaml.safe_load 不報 yaml 規則', () => {
  const out = scanRules('cfg = yaml.safe_load(stream)', { target: 't', language: 'python' });
  assert.equal(out.filter((f) => f.rule === 'insecure_config_yaml_load_without_loader').length, 0);
});

test('negative: bcrypt rounds 10 不報', () => {
  const out = scanRules('bcrypt.hash(password, 10)', { target: 't', language: 'javascript' });
  assert.equal(out.filter((f) => f.rule === 'ai_pattern_bcrypt_low_rounds').length, 0);
});

test('negative: 無害文字 → 空', () => {
  assert.deepEqual(scanRules('const x = 42;\nconsole.log("hello");', { target: 't', language: 'javascript' }), []);
});

// --- evidence 與定位 ---

test('evidence 用原文（這層不遮蔽）', () => {
  const [f] = scanRules('DEBUG = True', { target: 't', language: 'python' });
  assert.equal(f.evidence, 'DEBUG = True');
});

test('line/column/endLine/endColumn 正確', () => {
  const [f] = scanRules('ok = 1\neval(danger)', { target: 't', language: 'javascript' });
  assert.equal(f.line, 2);
  assert.equal(f.column, 1);
  assert.equal(f.endLine, 2);
  assert.ok(f.endColumn > f.column);
});

test('target 帶入 finding', () => {
  const [f] = scanRules('eval(x)', { target: 'src/app.js', language: 'javascript' });
  assert.equal(f.target, 'src/app.js');
});

test('重複掃描（regex lastIndex 重置）結果一致', () => {
  const text = 'eval(a)\neval(b)';
  const first = scanRules(text, { target: 't', language: 'javascript' });
  const second = scanRules(text, { target: 't', language: 'javascript' });
  assert.equal(first.length, 2);
  assert.deepEqual(first, second);
});
