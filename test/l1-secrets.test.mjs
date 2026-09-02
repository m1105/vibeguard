import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SECRET_RULES, scanSecrets, indexToLineCol } from '../shield/l1-secrets.mjs';
import { maskSecret } from '../shield/finding.mjs';

// fixture 一律執行期組合（fx）：GitHub 秘密掃描純看形狀，連明顯假的連號值都會當外洩；
// committed 檔案裡不得出現任何符合密鑰規則的字面值（repo-hygiene 測試把關）。這些全是假值。
const fx = (...parts) => parts.join('');

// --- indexToLineCol（照 DeepSec _position）---

test('indexToLineCol: first line, no newline before', () => {
  assert.deepEqual(indexToLineCol('hello world', 6), { line: 1, column: 7 });
});

test('indexToLineCol: second line after newline', () => {
  assert.deepEqual(indexToLineCol('hello\nworld', 6), { line: 2, column: 1 });
});

test('indexToLineCol: offset 0', () => {
  assert.deepEqual(indexToLineCol('abc', 0), { line: 1, column: 1 });
});

test('indexToLineCol: multiple lines', () => {
  // "a\nb\nc" → offset 4 is 'c', line 3, column 1
  assert.deepEqual(indexToLineCol('a\nb\nc', 4), { line: 3, column: 1 });
});

// --- SECRET_RULES export shape ---

test('SECRET_RULES: 11 entries, all with g flag', () => {
  assert.equal(SECRET_RULES.length, 11);
  for (const r of SECRET_RULES) {
    assert.ok(r.id, `rule has id`);
    assert.ok(r.regex instanceof RegExp, `${r.id} has regex`);
    assert.ok(r.regex.flags.includes('g'), `${r.id} has g flag`);
  }
});

// --- scanSecrets: 11 rules each hit its sample ---

test('scanSecrets: aws_access_key', () => {
  const text = 'key = "AKIAIOSFODNN7EXAMPLE"';
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_aws_access_key');
});

test('scanSecrets: github_token', () => {
  const text = 'token = "' + fx('ghp_', 'ABCDEFghijklMNOPQRstuvwx1234567890ABCD') + '"';
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_github_token');
});

test('scanSecrets: slack_token', () => {
  const text = fx('xoxb-', 'AbCdEfGhIjKlMnOpQrStUvWx');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_slack_token');
});

test('scanSecrets: stripe_key', () => {
  const text = ['sk_live', 'ABCDEFghijklMNOPQRstuvwx'].join('_'); // 執行期組合：GitHub push protection 純看形狀，字面寫出會被 GH013 拒推
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_stripe_key');
});

test('scanSecrets: google_api_key', () => {
  const text = fx('AIza', 'SyA1234567890abcdefghijklmnopqrstuv');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_google_api_key');
});

test('scanSecrets: npm_token', () => {
  const text = fx('npm_', 'ABCDEFghijklMNOPQRstuvwx1234567890AB');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_npm_token');
});

test('scanSecrets: anthropic_key', () => {
  const text = fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_anthropic_key');
});

test('scanSecrets: openai_key (sk-proj-)', () => {
  const text = fx('sk-proj-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_openai_key');
});

test('scanSecrets: jwt', () => {
  const text = fx('eyJ', 'abcdefghij1234567890.klmnopqrst1234567890.uvwxyzabcd1234567890');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_jwt');
});

test('scanSecrets: private_key', () => {
  const text = '-----BEGIN RSA PRIVATE KEY-----';
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_private_key');
});

test('scanSecrets: database_url', () => {
  const text = fx('postgres:', '//user:FAKEpass@db.example.com/db');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_database_url');
});

// --- sk-ant vs sk-proj discrimination ---

test('sk-ant hits anthropic_key but NOT openai_key', () => {
  const text = fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const out = scanSecrets(text);
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes('hardcoded_secret_anthropic_key'));
  assert.ok(!rules.includes('hardcoded_secret_openai_key'));
});

test('sk-proj hits openai_key but NOT anthropic_key', () => {
  const text = fx('sk-proj-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const out = scanSecrets(text);
  const rules = out.map((f) => f.rule);
  assert.ok(rules.includes('hardcoded_secret_openai_key'));
  assert.ok(!rules.includes('hardcoded_secret_anthropic_key'));
});

// --- database_url i flag (uppercase) ---

test(fx('POSTGRES:', '//u:FAKE@h/db') + ' hits database_url via i flag', () => {
  const text = fx('POSTGRES:', '//u:FAKE@h/db');
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  assert.equal(out[0].rule, 'hardcoded_secret_database_url');
});

// --- line/column from indexToLineCol ---

test('second-line secret: line=2, column correct', () => {
  const text = 'hello\nworld AKIAIOSFODNN7EXAMPLE';
  const out = scanSecrets(text);
  assert.equal(out.length, 1);
  // secret starts at offset 12; line 2, column 7 (w=1..space=6,A=7)
  assert.equal(out[0].line, 2);
  assert.equal(out[0].column, 7);
});

// --- evidence masking ---

test('evidence does not contain original long secret', () => {
  const raw = fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const out = scanSecrets(raw);
  assert.equal(out.length, 1);
  assert.ok(!out[0].evidence.includes(raw), 'evidence should be masked');
  assert.equal(out[0].evidence, maskSecret(raw));
});

// --- seenRanges mechanism ---

test('seenRanges: grows after hit; re-scan skips overlapping', () => {
  const text = 'key=' + fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');
  const seenRanges = [];
  const first = scanSecrets(text, { seenRanges });
  assert.ok(first.length >= 1);
  assert.equal(seenRanges.length, first.length); // each hit appends

  // re-scan with same seenRanges → all skipped
  const second = scanSecrets(text, { seenRanges });
  assert.equal(second.length, 0);
});

test('seenRanges: non-overlapping hits both reported', () => {
  const text = 'a=AKIAIOSFODNN7EXAMPLE b=' + fx('xoxb-', 'AbCdEfGhIjKlMnOpQrStUvWx');
  const seenRanges = [];
  const out = scanSecrets(text, { seenRanges });
  assert.equal(out.length, 2);
  assert.equal(seenRanges.length, 2);
});

// --- harmless text → empty ---

test('harmless text produces no findings', () => {
  const out = scanSecrets('const x = 42;\nconsole.log("hello world");');
  assert.deepEqual(out, []);
});

// --- finding shape ---

test('finding has correct layer/severity/type', () => {
  const out = scanSecrets('AKIAIOSFODNN7EXAMPLE');
  assert.equal(out[0].layer, 'L1');
  assert.equal(out[0].severity, 'critical');
  assert.equal(out[0].type, 'hardcoded_secret');
});

test('finding has Chinese title/description/suggestion', () => {
  const out = scanSecrets('AKIAIOSFODNN7EXAMPLE');
  assert.ok(out[0].title.length > 0);
  assert.ok(out[0].description.length > 0);
  assert.ok(out[0].suggestion.length > 0);
});
