
// fixture 一律執行期組合（fx）：GitHub 秘密掃描純看形狀，連明顯假的連號值都會當外洩；
// committed 檔案裡不得出現任何符合密鑰規則的字面值（repo-hygiene 測試把關）。這些全是假值。
const fx = (...parts) => parts.join('');
// e2e.test.mjs — 端到端驗證（純本地，不碰 Orca）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanText } from '../shield/scanner.mjs';
import { startPanelServer } from '../panel-server.mjs';

const EVIL = `const key = "${fx('sk-ant-', 'api03-aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQ')}";
const q = "DELETE FROM users; DROP TABLE users;";
const q2 = \`SELECT * FROM users WHERE id = \${req.query.id}\`;
`;

test('E2E: evil.js → 命中 anthropic_key(critical) + sql_template(high)，欄位齊全、evidence 已遮蔽', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'vibeguard-e2e-'));
  const file = join(dir, 'evil.js');
  await writeFile(file, EVIL);

  const text = await readFile(file, 'utf8');
  const { findings, layers, filesScanned } = await scanText(text, file, { l1: true, l2: true, l3: true, llm: false });

  assert.equal(filesScanned, 1);
  assert.ok(layers.includes('L1') && layers.includes('L2') && layers.includes('L3'));

  const key = findings.find((f) => f.rule === 'hardcoded_secret_anthropic_key');
  assert.ok(key, '應命中 anthropic_key');
  assert.equal(key.severity, 'critical');
  assert.equal(key.line, 1);

  const sql = findings.find((f) => f.rule === 'sast_sql_template_interpolation');
  assert.ok(sql, '應命中 sast_sql_template_interpolation');
  assert.equal(sql.severity, 'high');
  assert.equal(sql.line, 3);

  // 每筆欄位齊全
  for (const f of findings) {
    for (const field of ['layer', 'severity', 'type', 'rule', 'title', 'description', 'suggestion', 'target']) {
      assert.ok(f[field] !== undefined && f[field] !== null, `${f.rule} 缺 ${field}`);
    }
    assert.ok(f.line >= 1);
  }
  // 密鑰 evidence 不含完整原值
  assert.ok(!key.evidence.includes('aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQ'));
});

test('E2E: manifest 結構檢查（kebab-case、command id 格式、可 parse）', async () => {
  const raw = await readFile(new URL('../orca-plugin.json', import.meta.url), 'utf8');
  const m = JSON.parse(raw); // 可 parse
  const kebab = /^[a-z0-9]+(-[a-z0-9]+)*$/;
  assert.ok(kebab.test(m.id), m.id);
  assert.ok(kebab.test(m.publisher), m.publisher);
  assert.equal(m.pluginApi, 1);
  assert.equal(m.main, 'main.mjs');
  const cmdId = /^[A-Za-z0-9]+([._-][A-Za-z0-9]+)*$/;
  for (const c of m.contributes.commands) assert.ok(cmdId.test(c.id), c.id);
  const kinds = m.capabilities.map((c) => c.kind);
  for (const k of ['workspace:read', 'terminal:send', 'notifications:show', 'storage', 'events:subscribe']) {
    assert.ok(kinds.includes(k), k);
  }
  assert.equal(m.contributes.panels[0].entry, 'panel.html');
});

test('E2E: panel-server + 假資料 → fetch /findings 端到端（token 模型）', async () => {
  const server = await startPanelServer({
    token: 'e2e-token',
    getGroupedFindings: () => ({ wt1: { claude: [{ rule: 'r', target: '/a.js', line: 1 }] } }),
    openFile: async () => {},
    fixFinding: async () => ({ ok: true }),
  });
  try {
    assert.equal((await fetch(`${server.url}/findings`)).status, 403, '無 token 一律拒');
    const res = await fetch(`${server.url}/findings?token=e2e-token`);
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.wt1.claude[0].rule, 'r');
  } finally {
    await server.close();
  }
});
