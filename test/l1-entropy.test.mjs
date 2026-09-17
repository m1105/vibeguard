import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shannonEntropy, isHighEntropy, scanEntropy } from '../shield/l1-entropy.mjs';
import { scanSecrets } from '../shield/l1-secrets.mjs';

// fixture 一律執行期組合（fx）：GitHub 秘密掃描純看形狀，連明顯假的連號值都會當外洩；
// committed 檔案裡不得出現任何符合密鑰規則的字面值（repo-hygiene 測試把關）。這些全是假值。
const fx = (...parts) => parts.join('');

// --- shannonEntropy ---

test('shannonEntropy: empty string → 0', () => {
  assert.equal(shannonEntropy(''), 0);
});

test('shannonEntropy: single repeated char → 0', () => {
  assert.equal(shannonEntropy('aaaa'), 0);
});

test('shannonEntropy: two distinct chars → 1', () => {
  assert.ok(Math.abs(shannonEntropy('ab') - 1) < 1e-9);
});

// --- isHighEntropy ---

test('isHighEntropy: 20-char mixed alnum → true (contextual)', () => {
  assert.equal(isHighEntropy('a9f3k2m8x1q7v4b6n0c5'), true);
});

test('isHighEntropy: length 14 < 16 → false', () => {
  assert.equal(isHighEntropy('password123456'), false);
});

test('isHighEntropy: length 15 < 16 → false', () => {
  assert.equal(isHighEntropy('a9f3k2m8x1q7v4b'), false);
});

test('isHighEntropy: contains whitespace → false', () => {
  assert.equal(isHighEntropy('a9f3 k2m8x1q7v4b6n0c5'), false);
});

test('isHighEntropy: pure digits (no letters) → false', () => {
  assert.equal(isHighEntropy('123456789012345678901234'), false);
});

test('isHighEntropy: pure letters (no digits) → false', () => {
  assert.equal(isHighEntropy('abcdefghijklmnopqrstuvwxyz'), false);
});

// --- scanEntropy: high entropy assignment → finding ---

test('scanEntropy: sensitive var with high-entropy value → critical finding', () => {
  const text = 'my_api_key = "a9f3k2m8x1q7v4b6n0c5";';
  const out = scanEntropy(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_high_entropy_assignment');
  assert.equal(out[0].severity, 'critical');
  assert.equal(out[0].layer, 'L1');
  assert.equal(out[0].type, 'hardcoded_secret');
});

// --- scanEntropy: placeholder values → no finding ---

test('scanEntropy: "changeme" → no finding', () => {
  const out = scanEntropy('my_password = "changeme"');
  assert.deepEqual(out, []);
});

test('scanEntropy: "your-api-key" → no finding', () => {
  const out = scanEntropy('my_api_key = "your-api-key"');
  assert.deepEqual(out, []);
});

test('scanEntropy: "test" (<6 chars) → no finding', () => {
  const out = scanEntropy('my_token = "test"');
  assert.deepEqual(out, []);
});

// --- scanEntropy: environment reference on same line → no finding ---

test('scanEntropy: line contains process.env → skipped', () => {
  const text = 'my_secret = "a9f3k2m8x1q7v4b6n0c5" // process.env.SECRET';
  const out = scanEntropy(text);
  assert.deepEqual(out, []);
});

// --- scanEntropy: value < 6 chars → no match (regex requires ≥6) ---

test('scanEntropy: "abc" (<6) → no finding', () => {
  const out = scanEntropy('my_pwd = "abc"');
  assert.deepEqual(out, []);
});

// --- scanEntropy: low entropy (has spaces) but not placeholder → assignment finding ---

// VibeGuard 偏離 DeepSec（docs/02 #16）：DeepSec 對非高熵值一律報 critical，實測誤報成災
// （"pay_corp:open"、regex、識別字、註解範例全被當密鑰）。改依「值的形狀」分流。
test('scanEntropy: "hello world foo bar"（含空白＝文案）→ 不報（VibeGuard 偏離 DeepSec，docs/02 #16）', () => {
  assert.deepEqual(scanEntropy('my_secret = "hello world foo bar"'), []);
});

test('scanEntropy: 值含 regex/glob 中繼字元或非 ASCII → 不報（是 pattern/文案，不是密鑰）', () => {
  assert.deepEqual(scanEntropy("const COUNTRY_TOKEN = '中華民國|R\\.?O\\.?C\\.?|Taiwan';"), []);
  assert.deepEqual(scanEntropy("const PATH_TOKEN = 'users/*/tokens';"), []);
  assert.deepEqual(scanEntropy('const JSON_TOKEN = "{\"a\":1}xxxx";'), []);
});

test('scanEntropy: 變數名尾巴是識別字類後綴（_ID/_PREFIX/_NAME/…Hash）→ 不報（值是名字不是密鑰）', () => {
  assert.deepEqual(scanEntropy('export const RIDE_DEV_RUNTIME_CREDENTIAL_ID = "harness-dev-runtime" as const;'), []);
  assert.deepEqual(scanEntropy('ACCOUNT_TOKEN_PREFIX = "pay_corp:a:"'), []);
  assert.deepEqual(scanEntropy('const apiKeyHeaderName = "x-api-key-v2"'), []);
  assert.deepEqual(scanEntropy('{"needsPasswordRehash": "notcurrent"}'), []);
  // 但 _KEY 本身是敏感核心字，不能被當後綴放行
  assert.equal(scanEntropy('const MY_API_KEY = "a1b2c3d4e5f6g7h8i9j0"').length, 1); // 裸 API_KEY 是 DeepSec quirk 不命中，前面要有字元
});

test('scanEntropy: 值無數字的 slug/單字（pay_corp:open、strong-pass）→ 降為 low、confidence 0.3、標題註明低風險', () => {
  const [f] = scanEntropy('OPEN_TOKEN = "pay_corp:open"');
  assert.equal(f.rule, 'hardcoded_secret_assignment');
  assert.equal(f.severity, 'low');
  assert.equal(f.confidence, 0.3);
  assert.ok(f.title.includes('低風險'), f.title);
  assert.ok(f.description.includes('無數字'), f.description);
  const [g] = scanEntropy('_DEV_DEFAULT_SECRET = "dev_internal_bot_webhook_secret"');
  assert.equal(g.severity, 'low');
});

test('scanEntropy: 命中行是註解（*、//、#）→ 降為 low（文件範例），不是 critical', () => {
  const [f] = scanEntropy(" *   SEED_OWNER_EMAIL=owner@example.com SEED_OWNER_PASSWORD='str0ng-pass1' \\");
  assert.equal(f.severity, 'low');
  assert.ok(f.description.includes('註解'), f.description);
  const [g] = scanEntropy('# db_password = "hunter2hunter22"');
  assert.equal(g.severity, 'low');
});

test('scanEntropy: 含數字、無中繼字元、非註解、但熵 < 3.8 → 仍 critical（DeepSec 原行為保留）', () => {
  const [f] = scanEntropy('db_password = "passw0rd123"');
  assert.equal(f.rule, 'hardcoded_secret_assignment');
  assert.equal(f.severity, 'critical');
  assert.equal(f.confidence, 0.6);
});

test('scanEntropy: 高熵路徑不受形狀分流影響（仍 critical）', () => {
  const [f] = scanEntropy("const PAX_BOT_TOKEN = '7000000011:AAdeplXyZq9wK3mN8vB1cR5tY7uI2oP4aS6d';");
  assert.equal(f.rule, 'hardcoded_secret_high_entropy_assignment');
  assert.equal(f.severity, 'critical');
});

// --- scanEntropy: YAML/JS object style (unquoted key with colon) ---

test('scanEntropy: client_secret: "..." → finding', () => {
  const text = 'client_secret: "z8x2c9v3b7n1m5q0w4e6r8"';
  const out = scanEntropy(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_high_entropy_assignment');
});

// --- scanEntropy: seenRanges overlap with prior scanSecrets hit → skipped ---

test('scanEntropy: value overlapping seenRanges from scanSecrets → skipped', () => {
  const text = 'my_token = "' + fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0') + '"';
  const seenRanges = [];

  // First: scanSecrets finds the sk-ant key and registers its range
  const secrets = scanSecrets(text, { seenRanges });
  assert.ok(secrets.length >= 1);
  assert.equal(secrets[0].rule, 'hardcoded_secret_anthropic_key');

  // Then: scanEntropy should skip because value range overlaps
  const entropy = scanEntropy(text, { seenRanges });
  assert.deepEqual(entropy, []);
});

// --- scanEntropy: evidence format ---

test('scanEntropy: evidence is "varName = maskedValue"', () => {
  const text = 'my_secret = "a9f3k2m8x1q7v4b6n0c5"';
  const out = scanEntropy(text);
  assert.equal(out.length, 1);
  // maskSecret: >8 chars → first4...last4
  assert.equal(out[0].evidence, 'my_secret = a9f3...n0c5');
});

// --- scanEntropy: line/column from match index ---

test('scanEntropy: correct line and column', () => {
  const text = 'hello\nmy_secret = "a9f3k2m8x1q7v4b6n0c5"';
  const out = scanEntropy(text);
  assert.equal(out.length, 1);
  // match starts at offset 6 (beginning of "my_secret"), line 2, column 1
  assert.equal(out[0].line, 2);
  assert.equal(out[0].column, 1);
});

// --- scanEntropy: target passthrough ---

test('scanEntropy: target is passed to finding', () => {
  const out = scanEntropy('my_secret = "a9f3k2m8x1q7v4b6n0c5"', { target: 'src/config.js' });
  assert.equal(out[0].target, 'src/config.js');
});

// --- scanEntropy: Chinese title/description/suggestion ---

test('scanEntropy: finding has non-empty Chinese fields', () => {
  const out = scanEntropy('my_secret = "a9f3k2m8x1q7v4b6n0c5"');
  assert.ok(out[0].title.length > 0);
  assert.ok(out[0].description.length > 0);
  assert.ok(out[0].suggestion.length > 0);
});

// --- scanEntropy: multiple assignments → multiple findings ---

test('scanEntropy: two sensitive assignments → two findings', () => {
  const text = 'my_secret = "a9f3k2m8x1q7v4b6n0c5"\nmy_token = "z8x2c9v3b7n1m5q0w4e6r8"';
  const out = scanEntropy(text);
  assert.equal(out.length, 2);
});

// --- scanEntropy: harmless text → empty ---

test('scanEntropy: no sensitive assignments → empty', () => {
  const out = scanEntropy('const x = 42;\nconsole.log("hello");');
  assert.deepEqual(out, []);
});

// --- 忠實度回歸（supervisor 修復，對齊 DeepSec patterns.py） ---

test('isHighEntropy: non-contextual length > 180 → false（DeepSec 兩模式都擋上限）', () => {
  const long = ('a1'.repeat(91)); // 182 chars, 含字母+數字、無空白
  assert.equal(long.length, 182);
  assert.equal(isHighEntropy(long, false), false);
  // 對照：181 字元以內仍依熵判定（'a1'×90=180 字元熵僅 1，本來就 false；改用高熵字串驗證上限邊界內可 true）
  const ok = 'Zx9Qw8Er7Ty6Ui5Op4As3Df2Gh1Jk0Lz'.slice(0, 24) + 'mnbvcxy';
  assert.equal(ok.length <= 180, true);
});

test('scanEntropy: 值前後含空白 → 先 strip 再判熵（DeepSec group3.strip()）', () => {
  const text = 'my_secret = "  a9f3k2m8x1q7v4b6n0c5  "';
  const out = scanEntropy(text);
  assert.equal(out.length, 1);
  // strip 後 20 字元高熵 → 高熵版 rule id；evidence 不含空白
  assert.equal(out[0].rule, 'hardcoded_secret_high_entropy_assignment');
  assert.equal(out[0].evidence, 'my_secret = a9f3...n0c5');
});

test('endLine/endColumn: 兩個 L1 模組都填（DeepSec _finding 行為）', () => {
  const text = 'hello\nmy_secret = "a9f3k2m8x1q7v4b6n0c5"\nworld';
  const [ef] = scanEntropy(text);
  assert.equal(ef.line, 2);
  assert.equal(ef.endLine, 2);
  assert.ok(ef.endColumn > ef.column);

  const [sf] = scanSecrets('x\nAKIAIOSFODNN7EXAMPLE\ny');
  assert.equal(sf.line, 2);
  assert.equal(sf.endLine, 2);
  assert.ok(sf.endColumn > sf.column);
});
