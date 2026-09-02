import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SEVERITIES,
  LAYER_RANK,
  createFinding,
  uniqueFindings,
  maskSecret,
  coerceConfidence,
  coerceLine,
} from '../shield/finding.mjs';

// --- 常數匯出 ---

test('SEVERITIES / LAYER_RANK exports', () => {
  assert.deepEqual(SEVERITIES, ['critical', 'high', 'medium', 'low']);
  assert.deepEqual(LAYER_RANK, { L1: 1, L2: 2, L3: 3 });
});

// --- createFinding ---

test('createFinding({}) returns all defaults', () => {
  assert.deepEqual(createFinding({}), {
    layer: 'L1', severity: 'medium', type: '', rule: '', title: '',
    description: '', evidence: '', suggestion: '',
    line: null, column: null, endLine: null, endColumn: null,
    confidence: 0.6, foundAt: null, worktreeId: null, agent: null, target: null,
  });
});

test('createFinding passes through provided fields', () => {
  const f = createFinding({
    layer: 'L3', severity: 'high', type: 'T', rule: 'r1', title: 't',
    description: 'd', evidence: 'e', suggestion: 's',
    line: 7, column: 3, endLine: 9, endColumn: 5,
    confidence: 0.9, worktreeId: 'w1', agent: 'claude', target: '/a/b.js',
  });
  assert.equal(f.layer, 'L3');
  assert.equal(f.severity, 'high');
  assert.equal(f.type, 'T');
  assert.equal(f.rule, 'r1');
  assert.equal(f.title, 't');
  assert.equal(f.description, 'd');
  assert.equal(f.evidence, 'e');
  assert.equal(f.suggestion, 's');
  assert.equal(f.line, 7);
  assert.equal(f.column, 3);
  assert.equal(f.endLine, 9);
  assert.equal(f.endColumn, 5);
  assert.equal(f.confidence, 0.9);
  assert.equal(f.worktreeId, 'w1');
  assert.equal(f.agent, 'claude');
  assert.equal(f.target, '/a/b.js');
});

test('createFinding severity: only lowercase list accepted, else medium', () => {
  assert.equal(createFinding({ severity: 'HIGH' }).severity, 'medium');
  assert.equal(createFinding({ severity: 'foo' }).severity, 'medium');
  assert.equal(createFinding({ severity: 'critical' }).severity, 'critical');
});

test('createFinding invalid layer falls back to L1', () => {
  assert.equal(createFinding({ layer: 'L9' }).layer, 'L1');
});

test('createFinding coerces line and confidence inputs', () => {
  assert.equal(createFinding({ line: '42' }).line, 42);
  assert.equal(createFinding({ confidence: 'high' }).confidence, 0.85);
});

// --- coerceLine（照 ai_audit._coerce_line）---

test('coerceLine number rules', () => {
  assert.equal(coerceLine(42), 42);
  assert.equal(coerceLine(0), 1);      // max(1, 0)
  assert.equal(coerceLine(-3), 1);     // max(1, -3)
  assert.equal(coerceLine(3.0), 3);    // float 整數值
  assert.equal(coerceLine(3.7), null); // float 非整數值
});

test('coerceLine string / bool / other rules', () => {
  assert.equal(coerceLine('42'), 42);
  assert.equal(coerceLine('abc'), null);
  assert.equal(coerceLine(true), null); // bool → null（先於 number 判斷）
  assert.equal(coerceLine(null), null);
});

// --- coerceConfidence（照 ai_audit._coerce_confidence）---

test('coerceConfidence number: clamp 0–1, no /100', () => {
  assert.equal(coerceConfidence(0.8), 0.8);
  assert.equal(coerceConfidence(1.5), 1); // clamp，不除 100
});

test('coerceConfidence string: lookup table, %, /100', () => {
  assert.equal(coerceConfidence('80%'), 0.8);
  assert.equal(coerceConfidence('80'), 0.8); // >1 → /100
  assert.equal(coerceConfidence('high'), 0.85);
  assert.equal(coerceConfidence('very low'), 0.2);
  assert.equal(coerceConfidence('nonsense'), 0.6); // 不在表且 parseFloat 失敗
});

test('coerceConfidence bool/null/undefined → 0.6', () => {
  assert.equal(coerceConfidence(true), 0.6);
  assert.equal(coerceConfidence(false), 0.6);
  assert.equal(coerceConfidence(null), 0.6);
  assert.equal(coerceConfidence(undefined), 0.6);
});

// --- maskSecret（照 patterns._redact）---

test('maskSecret', () => {
  assert.equal(maskSecret('abc'), '***');        // ≤8 → ***
  assert.equal(maskSecret('12345678'), '***');   // =8 → ***
  assert.equal(maskSecret('abcdefghij'), 'abcd...ghij'); // >8 → 前4...後4
});

// --- uniqueFindings（全域去重 + 跨層合併）---

test('uniqueFindings dedups by (rule,target,line,evidence), keeps first', () => {
  const a = createFinding({ rule: 'r1', target: 't', line: 1, evidence: 'e', title: 'first' });
  const b = createFinding({ rule: 'r1', target: 't', line: 1, evidence: 'e', title: 'second' });
  const out = uniqueFindings([a, b]);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'first');
});

test('uniqueFindings cross-layer: same (type,target,line) keeps highest layer at first position', () => {
  const l1 = createFinding({ rule: 'r1', target: 't', line: 5, evidence: 'e1', type: 'T' }); // L1
  const l3 = createFinding({ rule: 'r2', target: 't', line: 5, evidence: 'e2', type: 'T', layer: 'L3' });
  const other = createFinding({ rule: 'r3', target: 't', line: 6, evidence: 'e3', type: 'T' }); // 不同 line
  const out = uniqueFindings([l1, l3, other]);
  assert.equal(out.length, 2);
  assert.equal(out[0].layer, 'L3'); // L3 勝出，佔第一次出現的位置
  assert.equal(out[1].line, 6);     // 不同 line 保留，順序穩定
});

test('uniqueFindings same rank keeps first-appearing', () => {
  const a = createFinding({ rule: 'r1', target: 't2', line: 9, evidence: 'x1', type: 'G', title: 'a' });
  const b = createFinding({ rule: 'r2', target: 't2', line: 9, evidence: 'x2', type: 'G', title: 'b' });
  const out = uniqueFindings([a, b]);
  assert.equal(out.length, 1);
  assert.equal(out[0].title, 'a');
});

test('uniqueFindings keeps distinct lines in original order', () => {
  const f1 = createFinding({ rule: 'r1', target: 't', line: 2, evidence: 'a' });
  const f2 = createFinding({ rule: 'r1', target: 't', line: 3, evidence: 'b' });
  const f3 = createFinding({ rule: 'r1', target: 't', line: 1, evidence: 'c' });
  const out = uniqueFindings([f1, f2, f3]);
  assert.deepEqual(out.map((f) => f.line), [2, 3, 1]);
});

// ── finding 身分（不含行號）──
// agent 在檔案上方插幾行 → 全檔行號位移 → 含行號的身分會讓舊 finding 全被判「已修正」、
// 新的全掛 NEW，連 meaningfulHash 都跟著變（面板一直重烤重掛，使用者捲不動）。
test('identity：整體行號位移，身分不變（同內容 = 同一個問題）', async () => {
  const { assignIdentities } = await import('../shield/finding.mjs');
  const mk = (line, text) => ({
    rule: 'insecure_config_acao_wildcard', target: '/repo/routes.ts', title: 'ACAO 萬用字元',
    line, snippet: [{ ln: line - 1, text: 'a' }, { ln: line, text }, { ln: line + 1, text: 'b' }],
  });
  const before = assignIdentities([mk(175, "res.setHeader('ACAO', '*')"), mk(220, "cors({ origin: '*' })")]);
  const after = assignIdentities([mk(180, "res.setHeader('ACAO', '*')"), mk(225, "cors({ origin: '*' })")]);
  assert.equal(before[0].identity, after[0].identity, '行號 +5 不該產生新身分');
  assert.equal(before[1].identity, after[1].identity);
  assert.notEqual(before[0].identity, before[1].identity, '命中內容不同 → 不同身分');
});

test('identity：同檔同規則同內容多筆（ACAO x6）靠序號區分，位移後仍一一對應', async () => {
  const { assignIdentities } = await import('../shield/finding.mjs');
  const line = "  res.setHeader('Access-Control-Allow-Origin', '*');";
  const mk = (n) => ({ rule: 'acao', target: '/r.ts', title: 'ACAO', line: n, snippet: [{ ln: n, text: line }] });
  const before = assignIdentities([175, 220, 259].map(mk));
  const after = assignIdentities([180, 225, 264].map(mk));
  assert.deepEqual(before.map((f) => f.identity), after.map((f) => f.identity));
  assert.equal(new Set(before.map((f) => f.identity)).size, 3, '同內容多筆要各自有身分，不能塌成一筆');
});

test('identity：沒有 snippet 時退回 evidence；兩者都沒有也要穩定不炸', async () => {
  const { assignIdentities, identityOf } = await import('../shield/finding.mjs');
  const a = { rule: 'r', target: '/f.ts', title: 't', line: 10, evidence: 'const x = 1' };
  const b = { rule: 'r', target: '/f.ts', title: 't', line: 99, evidence: 'const x = 1' };
  assignIdentities([a]); assignIdentities([b]);
  assert.equal(a.identity, b.identity, 'evidence 相同 → 同身分');
  const bare = { rule: 'r', target: '/f.ts', title: 't', line: 3 };
  assert.equal(typeof identityOf(bare), 'string');
  assert.ok(identityOf(bare).length > 0);
  // identityOf 對已標記的沿用既有值（舊資料沒有就現算）
  assert.equal(identityOf(a), a.identity);
});
