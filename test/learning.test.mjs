import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LEARNED_FILENAME, normalizeTitle, parseLearned, serializeLearned, isLearned, addLearned,
} from '../shield/learning.mjs';

test('normalizeTitle：大小寫/空白正規化', () => {
  assert.equal(normalizeTitle('  敏感端點\n缺少認證 '), '敏感端點 缺少認證');
  assert.equal(normalizeTitle('Missing AUTH Check'), 'missing auth check');
  assert.equal(normalizeTitle(null), '');
});

test('parseLearned：壞 JSON / 非陣列 / 無效條目都擋掉', () => {
  assert.deepEqual(parseLearned('not json'), []);
  assert.deepEqual(parseLearned('{"a":1}'), []);
  assert.deepEqual(parseLearned('[{"rule":"r"},{"rule":"r","target":"t","title":"x"}]'), [
    { rule: 'r', target: 't', title: 'x' },
  ]);
});

test('serialize/parse 往返', () => {
  const entries = [{ rule: 'r1', target: 'a/b.ts', title: '缺限流', at: '2026-08-30T00:00:00Z' }];
  assert.deepEqual(parseLearned(serializeLearned(entries)), entries);
});

test('isLearned：同 rule + 同檔 + 同標題才算；不同檔不算', () => {
  const entries = [{ rule: 'l3_llm_semantic_review', target: 'src/routes.ts', title: '錢包儲值端點缺少金額校驗與限流' }];
  const f = { rule: 'l3_llm_semantic_review', title: '錢包儲值端點缺少金額校驗與限流' };
  assert.equal(isLearned(f, entries, 'src/routes.ts'), true);
  assert.equal(isLearned(f, entries, 'src/other.ts'), false);
  assert.equal(isLearned({ ...f, title: '別的問題' }, entries, 'src/routes.ts'), false);
});

test('addLearned：去重（同 rule+檔+標題不重複記）', () => {
  const f = { rule: 'r', title: 'T' };
  const a = addLearned([], f, 'x.ts', 't1');
  assert.equal(a.length, 1);
  const b = addLearned(a, f, 'x.ts', 't2');
  assert.equal(b.length, 1);
  assert.equal(b[0].at, 't1'); // 保留最早一筆
});

test('addLearned：無 rel 路徑不記；超過 100 筆丟最舊', () => {
  const f = { rule: 'r', title: 'T' };
  assert.deepEqual(addLearned([], f, null, 't'), []);
  let list = [];
  for (let i = 0; i < 105; i++) list = addLearned(list, { rule: 'r', title: `T${i}` }, 'x.ts', 't');
  assert.equal(list.length, 100);
  assert.equal(list[0].title, 'T5'); // T0~T4 被擠掉
});

test('LEARNED_FILENAME 是 .vibeguard-learned.json', () => {
  assert.equal(LEARNED_FILENAME, '.vibeguard-learned.json');
});
