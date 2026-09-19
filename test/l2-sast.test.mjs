import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SAST_RULES, scanSast } from '../shield/l2-sast.mjs';

// --- 規則表結構 ---

test('rule table: 16 條，id 前綴 sast_，欄位齊全，全帶 g flag', () => {
  assert.equal(SAST_RULES.length, 16);
  for (const r of SAST_RULES) {
    assert.ok(r.id.startsWith('sast_'), r.id);
    assert.ok(r.type && r.severity && r.title && r.description && r.suggestion, r.id);
    assert.ok(r.regex.global, r.id);
  }
});

test('flags: 只有 sast_xss_inner_html 無 i（DeepSec flags=0），其餘有 i', () => {
  for (const r of SAST_RULES) {
    if (r.id === 'sast_xss_inner_html') {
      assert.equal(r.regex.ignoreCase, false, r.id);
    } else {
      assert.equal(r.regex.ignoreCase, true, r.id);
    }
  }
});

// --- 每條規則一個命中樣本 ---

const HITS = [
  ['sast_sql_template_interpolation', 'const q = `SELECT * FROM users WHERE id = ${userId}`;'],
  ['sast_sql_string_concat', 'const q = "SELECT * FROM u WHERE n = \'" + name;'],
  ['sast_sql_python_f_string_execute', 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'],
  ['sast_sql_user_input_execute', 'db.query(sql, req.body.id)'],
  ['sast_sql_concat_execute', 'cursor.execute("SELECT * FROM u WHERE n = \'" + name + "\'")'],
  ['sast_xss_inner_html', 'el.innerHTML = userHtml'],
  ['sast_xss_document_write', 'document.write(userHtml)'],
  ['sast_xss_dangerously_set_inner_html', 'dangerouslySetInnerHTML={{__html: req.query.html}}'],
  ['sast_ssrf_fetch_user_url', 'fetch(req.query.url)'],
  ['sast_path_traversal_fs_user_input', 'fs.readFile(req.query.path)'],
  ['sast_insecure_deserialization_pickle', 'pickle.loads(request.data)'],
  ['sast_insecure_deserialization_yaml', 'yaml.load(request.data)'],
  ['sast_command_injection_os_system', 'os.system("ping " + request.args["host"])'],
  ['sast_command_injection_shell_true', 'subprocess.run(cmd, shell=True)'],
  ['sast_open_redirect_user_input', 'res.redirect(req.query.next)'],
  ['sast_information_leakage_error_details', 'res.json({ error: err.stack })'],
];

for (const [id, snippet] of HITS) {
  test(`hit: ${id}`, () => {
    const out = scanSast(snippet, { target: 't' });
    const hit = out.find((f) => f.rule === id);
    assert.ok(hit, `expected ${id} to fire on: ${snippet}`);
    assert.equal(hit.layer, 'L2');
    assert.ok(hit.line >= 1);
  });
}

// --- severity / type 抽樣（逐字照 DeepSec） ---

test('severity: medium 的只有 ssrf / open_redirect / information_leakage，其餘 high', () => {
  const sev = Object.fromEntries(SAST_RULES.map((r) => [r.id, r.severity]));
  assert.equal(sev['sast_ssrf_fetch_user_url'], 'medium');
  assert.equal(sev['sast_open_redirect_user_input'], 'medium');
  assert.equal(sev['sast_information_leakage_error_details'], 'medium');
  for (const r of SAST_RULES) {
    if (!['sast_ssrf_fetch_user_url', 'sast_open_redirect_user_input', 'sast_information_leakage_error_details'].includes(r.id)) {
      assert.equal(r.severity, 'high', r.id);
    }
  }
});

test('type 對應正確', () => {
  const ty = Object.fromEntries(SAST_RULES.map((r) => [r.id, r.type]));
  assert.equal(ty['sast_sql_template_interpolation'], 'sql_injection');
  assert.equal(ty['sast_xss_inner_html'], 'xss');
  assert.equal(ty['sast_ssrf_fetch_user_url'], 'ssrf');
  assert.equal(ty['sast_path_traversal_fs_user_input'], 'path_traversal');
  assert.equal(ty['sast_insecure_deserialization_pickle'], 'insecure_deserialization');
  assert.equal(ty['sast_command_injection_os_system'], 'command_injection');
  assert.equal(ty['sast_open_redirect_user_input'], 'open_redirect');
  assert.equal(ty['sast_information_leakage_error_details'], 'information_leakage');
});

// --- 負向案例 ---

test('negative: 參數化查詢不報', () => {
  const out = scanSast('db.query("SELECT * FROM u WHERE id=?", [id])', { target: 't' });
  assert.deepEqual(out, []);
});

test('negative: innerHTML=DOMPurify（無空格）不報', () => {
  const out = scanSast('el.innerHTML=DOMPurify.sanitize(x)', { target: 't' });
  assert.equal(out.filter((f) => f.rule === 'sast_xss_inner_html').length, 0);
});

test('fidelity quirk: regex 層 innerHTML = DOMPurify（有空格）仍命中；但 scanSast 的右值分析認出已消毒 → 不報（docs/02 #17）', () => {
  // \s* 回溯讓負向前瞻失效，Python 版行為相同——regex 逐字保留（忠實度），
  // 誤報改由命中後的右值分析（l2-xss-triage）吸收：DOMPurify.sanitize(x) 涵蓋整個右值 = escaped
  const rule = SAST_RULES.find((r) => r.id === 'sast_xss_inner_html');
  rule.regex.lastIndex = 0;
  assert.ok(rule.regex.test('el.innerHTML = DOMPurify.sanitize(x)'), 'regex quirk 仍在');
  rule.regex.lastIndex = 0;
  const out = scanSast('el.innerHTML = DOMPurify.sanitize(x)', { target: 't' });
  assert.equal(out.filter((f) => f.rule === 'sast_xss_inner_html').length, 0);
  // 消毒只包一部分就不放行
  const partial = scanSast('el.innerHTML = DOMPurify.sanitize(x) + y', { target: 't' });
  assert.equal(partial.filter((f) => f.rule === 'sast_xss_inner_html')[0].severity, 'medium');
});

test('negative: yaml.load + SafeLoader 不報（負向前瞻）', () => {
  const out = scanSast('yaml.load(request.data, Loader=SafeLoader)', { target: 't' });
  assert.equal(out.filter((f) => f.rule === 'sast_insecure_deserialization_yaml').length, 0);
});

test('negative: 無害碼 → 空', () => {
  assert.deepEqual(scanSast('const x = 42;\nconsole.log("hello");', { target: 't' }), []);
});

// --- dedup：(type, line) 留先 ---

test('dedup: 同行兩條 sql_injection 規則命中 → 只回一筆', () => {
  // 同一行同時命中規則 1（模板插值）與規則 4（db.query + req.）
  const text = 'const q = `SELECT * FROM users WHERE id = ${req.query.id}`; db.query(q, req.query.id)';
  const out = scanSast(text, { target: 't' });
  const sql = out.filter((f) => f.type === 'sql_injection' && f.line === 1);
  assert.equal(sql.length, 1);
  // 留先出現者：規則 1 在規則表排前面
  assert.equal(sql[0].rule, 'sast_sql_template_interpolation');
});

test('dedup: 不同行同 type 不去重', () => {
  const text = 'fetch(req.query.a)\nfetch(req.query.b)';
  const out = scanSast(text, { target: 't' });
  assert.equal(out.filter((f) => f.type === 'ssrf').length, 2);
});

// --- evidence 與定位 ---

test('evidence 用原文（這層不遮蔽）', () => {
  const [f] = scanSast('document.write(x)', { target: 't' });
  assert.equal(f.evidence, 'document.write('); // regex 只比對到左括號
});

test('line/column 正確', () => {
  const [f] = scanSast('ok = 1\ndocument.write(x)', { target: 't' });
  assert.equal(f.line, 2);
  assert.equal(f.column, 1);
});

test('target 帶入 finding', () => {
  const [f] = scanSast('document.write(x)', { target: 'src/app.js' });
  assert.equal(f.target, 'src/app.js');
});

test('重複掃描（regex lastIndex 重置）結果一致', () => {
  const text = 'document.write(a)\ndocument.write(b)';
  const first = scanSast(text, { target: 't' });
  const second = scanSast(text, { target: 't' });
  assert.equal(first.length, 2);
  assert.deepEqual(first, second);
});

test('sast_xss_inner_html：純空字串賦值（清空容器）不報——回溯打穿豁免前瞻的誤報修正', async () => {
  const { scanSast } = await import('../shield/l2-sast.mjs');
  // `= ''` 帶空格時 \s* 回溯會讓豁免前瞻看到空格而失效（DeepSec 原版同病，docs/02 記差異）
  for (const code of ["box.innerHTML = '';", 'sel.innerHTML = "";', 'el.outerHTML = ``;', "a.innerHTML='';"]) {
    const hits = scanSast(code).filter((f) => f.rule === 'sast_xss_inner_html');
    assert.equal(hits.length, 0, code + ' 不該報');
  }
  // 真的有風險的照報
  const real = scanSast("order.innerHTML = payload.html;").filter((f) => f.rule === 'sast_xss_inner_html');
  assert.equal(real.length, 1);
});
