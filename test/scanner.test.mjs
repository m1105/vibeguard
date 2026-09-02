import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  SUPPORTED_SUFFIXES, IGNORED_DIRECTORIES, TEST_DIRECTORIES,
  GENERATED_SUFFIXES, TEST_FILE_MARKERS, REPORT_FILENAMES,
  MAX_FILE_BYTES, detectLanguage, shouldSkipPath, scanText,
} from '../shield/scanner.mjs';
import { createFinding } from '../shield/finding.mjs';

// --- shouldSkipPath ---

test('shouldSkipPath: 正常檔不跳', () => {
  assert.equal(shouldSkipPath('src/a.js'), false);
  assert.equal(shouldSkipPath('src/deep/b.py'), false);
});

test('shouldSkipPath: 不支援副檔名 → 跳', () => {
  assert.equal(shouldSkipPath('README.md'), true);
  assert.equal(shouldSkipPath('image.png'), true);
});

test('shouldSkipPath: 忽略目錄 → 跳', () => {
  assert.equal(shouldSkipPath('node_modules/x/y.js'), true);
  assert.equal(shouldSkipPath('dist/b.js'), true);
  assert.equal(shouldSkipPath('.venv311/lib/a.py'), true); // startswith .venv
  assert.equal(shouldSkipPath('venv-3/lib/a.py'), true); // startswith venv-
  assert.equal(shouldSkipPath('venv3/lib/a.py'), true);
});

test('shouldSkipPath: 生成檔/報告檔 → 跳', () => {
  assert.equal(shouldSkipPath('dist/b.min.js'), true);
  assert.equal(shouldSkipPath('package-lock.json'), true);
  assert.equal(shouldSkipPath('deepsec-report.json'), true);
  assert.equal(shouldSkipPath('x/y.pb.go'), true);
  assert.equal(shouldSkipPath('x/z_pb2.py'), true);
});

test('shouldSkipPath: 測試檔預設跳、includeTests=true 放行', () => {
  assert.equal(shouldSkipPath('src/a.test.ts'), true);
  assert.equal(shouldSkipPath('src/a.test.ts', { includeTests: true }), false);
  assert.equal(shouldSkipPath('tests/x.py'), true);
  assert.equal(shouldSkipPath('tests/x.py', { includeTests: true }), false);
  assert.equal(shouldSkipPath('__tests__/y.js'), true);
});

test('shouldSkipPath: 翻譯/文案檔跳過（i18n 字串常被誤判成硬編碼密鑰）', () => {
  assert.equal(shouldSkipPath('apps/admin/src/i18n/zh-Hant.ts'), true);
  assert.equal(shouldSkipPath('src/locales/en.json'), true);
  assert.equal(shouldSkipPath('src/l10n/messages.ts'), true);
  // 一般 src 檔不受影響
  assert.equal(shouldSkipPath('src/i18n-utils/parse.ts'), false);
});

test('清單常數形狀', () => {
  assert.equal(Object.keys(SUPPORTED_SUFFIXES).length, 16);
  assert.ok(IGNORED_DIRECTORIES.has('node_modules'));
  assert.ok(TEST_DIRECTORIES.has('__tests__'));
  assert.ok(GENERATED_SUFFIXES.includes('_pb2.py'));
  assert.deepEqual(TEST_FILE_MARKERS, ['.test.', '.spec.', '_test.', '_spec.']);
  assert.ok(REPORT_FILENAMES.has('deepsec-report.json'));
  assert.equal(MAX_FILE_BYTES, 500 * 1024);
});

// --- detectLanguage ---

test('detectLanguage: 副檔名小寫查表', () => {
  assert.equal(detectLanguage('a.PY'), 'python');
  assert.equal(detectLanguage('b.tsx'), 'tsx');
  assert.equal(detectLanguage('c.txt'), null);
  assert.equal(detectLanguage('x/y/z.mjs'), 'javascript');
});

// --- scanText ---

test('scanText: 全開（l1+l2+l3+llm）→ layers 齊、findings 含各層', async () => {
  const text = 'const k = "AKIAIOSFODNN7EXAMPLE";\ndocument.write(x)\n' +
    "app.post('/admin/reset', (req, res) => {\n  const u = req.body.u;\n})";
  const fakeLlm = async () => [createFinding({ layer: 'L3', rule: 'l3_llm_semantic_review', type: 'missing_security_measure', target: 'a.js', line: 1 })];
  const r = await scanText(text, 'a.js', { l1: true, l2: true, l3: true, llm: true }, { llmScan: fakeLlm });
  assert.deepEqual(r.layers, ['L1', 'L2', 'L3', 'LLM']);
  assert.equal(r.filesScanned, 1);
  assert.ok(r.findings.some((f) => f.rule === 'hardcoded_secret_aws_access_key'));
  assert.ok(r.findings.some((f) => f.rule === 'sast_xss_document_write'));
  assert.ok(r.findings.some((f) => f.rule === 'l3_missing_authentication'));
  assert.ok(r.findings.some((f) => f.rule === 'l3_llm_semantic_review'));
  assert.ok(r.elapsedMs >= 0);
});

test('scanText: llmScan 丟例外 → 正常回傳、layers 含 LLM_FAILED', async () => {
  const bad = async () => { throw new Error('boom'); };
  const r = await scanText('const x = 1;', 'a.js', { llm: true }, { llmScan: bad });
  assert.ok(r.layers.includes('LLM_FAILED'));
  assert.equal(r.filesScanned, 1);
});

test('scanText: llmScan 未提供 → LLM_FAILED', async () => {
  const r = await scanText('const x = 1;', 'a.js', { llm: true });
  assert.ok(r.layers.includes('LLM_FAILED'));
});

test('scanText: options.learned 傳給 llmScan（誤報學習）', async () => {
  const learned = [{ rule: 'r', target: 'a.js', title: '已確認誤報' }];
  let seen = null;
  const spy = async (input) => { seen = input; return []; };
  await scanText('const x = 1;', 'a.js', { llm: true, learned }, { llmScan: spy });
  assert.deepEqual(seen.learned, learned);
});

test('scanText: 預設 l3/llm 關閉', async () => {
  const r = await scanText("app.post('/admin/reset', (req, res) => {\n  const u = req.body.u;\n})", 'a.js');
  assert.deepEqual(r.layers, ['L1', 'L2']);
  assert.ok(!r.findings.some((f) => f.layer === 'L3'));
});

test('scanText: >500KB → skipped too_large', async () => {
  const r = await scanText('x'.repeat(MAX_FILE_BYTES + 1), 'a.js');
  assert.equal(r.skipped, 'too_large');
  assert.equal(r.filesScanned, 0);
  assert.deepEqual(r.findings, []);
});

test('scanText: AKIA 密鑰 → 至少一筆 critical', async () => {
  const r = await scanText('const k = "AKIAIOSFODNN7EXAMPLE";', 'a.js');
  assert.ok(r.findings.some((f) => f.severity === 'critical'));
});

test('scanText: ignoreRuleIds 命中即移除', async () => {
  const text = 'const k = "AKIAIOSFODNN7EXAMPLE";';
  const r = await scanText(text, 'a.js', { ignoreRuleIds: new Set(['hardcoded_secret_aws_access_key']) });
  assert.equal(r.findings.filter((f) => f.rule === 'hardcoded_secret_aws_access_key').length, 0);
});

test('scanText: dedup 關閉時不去重', async () => {
  // JWT_SECRET 同時命中 entropy 賦值規則與 ai_pattern_hardcoded_jwt_secret
  const text = 'JWT_SECRET = "a9f3k2m8x1q7v4b6n0c5z8x2"';
  const on = await scanText(text, 'a.js', { dedup: true });
  const off = await scanText(text, 'a.js', { dedup: false });
  assert.ok(off.findings.length >= on.findings.length);
});

test('shouldSkipPath: agent 狀態目錄（.omc/.claude）跳過', () => {
  assert.equal(shouldSkipPath('/x/.omc/state/hud.json'), true);
  assert.equal(shouldSkipPath('/x/.claude/settings.json'), true);
});

test('shouldSkipPath：.vibeguard-learned.json 不掃（學習檔記錄規則名，會被 L2 當命中——自我掃描誤報）', async () => {
  const { shouldSkipPath } = await import('../shield/scanner.mjs');
  assert.equal(shouldSkipPath('/repo/.vibeguard-learned.json'), true);
  assert.equal(shouldSkipPath('/repo/sub/.vibeguard-learned.json'), true);
});

test('shouldSkipPath：.omx/.serena 等 agent 工具狀態目錄不掃（高頻變動、白燒 LLM）', async () => {
  const { shouldSkipPath } = await import('../shield/scanner.mjs');
  assert.equal(shouldSkipPath('/repo/.omx/state/session.json'), true);
  assert.equal(shouldSkipPath('/repo/.serena/memories/x.md'), true);
  assert.equal(shouldSkipPath('/repo/.codegraph/codegraph.db'), true);
});

test('scanText：LLM 失敗時回傳 llmError（失敗原因要看得到，不再黑箱）', async () => {
  const { scanText } = await import('../shield/scanner.mjs');
  const r = await scanText('const a = 1;', '/x/a.js', { l1: true, l2: false, l3: false, llm: true },
    { llmScan: async () => { throw new Error('claude exited 1: OAuth expired'); } });
  assert.ok(r.layers.includes('LLM_FAILED'));
  assert.ok(String(r.llmError).includes('OAuth expired'), 'llmError 要帶真因');
});
