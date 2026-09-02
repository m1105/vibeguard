import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactForLlm, REDACTED } from '../shield/redaction.mjs';

// fixture 一律執行期組合（fx）：GitHub 秘密掃描純看形狀，連明顯假的連號值都會當外洩；
// committed 檔案裡不得出現任何符合密鑰規則的字面值（repo-hygiene 測試把關）。這些全是假值。
const fx = (...parts) => parts.join('');

const SK_ANT = fx('sk-ant-', 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0');

test('密鑰整段替換，原值完全消失', () => {
  const { text, count } = redactForLlm(`const k = "${SK_ANT}";`);
  assert.ok(!text.includes(SK_ANT));
  assert.ok(text.includes(REDACTED));
  assert.equal(count, 1);
});

test('敏感賦值只換值，保留 name = "..." 結構', () => {
  // 注意：DeepSec 的賦值 regex 要求關鍵字前至少有 1 字元，所以裸 `apiKey`/`secret` 不會命中
  // （Python 實測相同，屬原作行為）。這裡用 my_api_key 驗證替換結構。
  const { text, count } = redactForLlm('my_api_key = "a9f3k2m8x1q7v4b6n0c5"');
  assert.equal(text, `my_api_key = "${REDACTED}"`);
  assert.equal(count, 1);
  assert.ok(!text.includes('a9f3k2m8x1q7v4b6n0c5'));
});

test('密鑰 + 敏感賦值各算一次', () => {
  const { count } = redactForLlm(`const k = "${SK_ANT}";\nmy_api_key = "a9f3k2m8x1q7v4b6n0c5"`);
  assert.equal(count, 2);
});

test('database URL 整段替換', () => {
  const { text, count } = redactForLlm('const db = "' + fx('postgres:', '//user:FAKEpassw0rd@db.example.com:5432/app') + '";');
  assert.ok(!text.includes('passw0rd'));
  assert.ok(!text.includes('db.example.com'));
  assert.equal(count, 1);
});

test('無密碼文字原樣返回 count 0', () => {
  const src = 'const x = 42;\nconsole.log("hello");';
  const { text, count } = redactForLlm(src);
  assert.equal(text, src);
  assert.equal(count, 0);
});

test('重複呼叫結果一致（regex lastIndex 無殘留）', () => {
  const src = `const k = "${SK_ANT}";`;
  assert.deepEqual(redactForLlm(src), redactForLlm(src));
});
