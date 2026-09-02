// repo-hygiene.test.mjs — 機敏資料閘門（開源前提：任何會進 git 的檔案都不得含真密鑰、私人路徑、信箱）。
//
// 為什麼放在 npm test：文件/註解/測試 fixture 也是「會被公開的內容」，靠人眼檢查會漏。
// 這裡拿本專案自己的 L1 密鑰規則掃全部「會進版控的檔案」（git ls-files 含未追蹤但未被 ignore 的），
// 命中的字串必須「一眼看得出是假的」（EXAMPLE / FAKE / 連續字母 …），否則測試失敗。
// 這也是 dogfooding：掃描器抓不到的假密鑰形狀，代表規則有漏。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { SECRET_RULES } from '../shield/l1-secrets.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const TEXT_EXT = new Set(['.mjs', '.js', '.cjs', '.ts', '.json', '.md', '.txt', '.yml', '.yaml', '.html', '.sh', '']);
const SKIP_DIRS = new Set(['.git', 'node_modules', '.omc', '.omx', '.serena', '.codegraph', '.claude']);

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (SKIP_DIRS.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else out.push(relative(ROOT, p));
  }
  return out;
}

// 會進版控的檔案：已追蹤 + 未追蹤但沒被 .gitignore 擋的（= 下一次 git add -A 會進去的）
function candidateFiles() {
  try {
    const out = execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: ROOT, stdio: ['ignore', 'pipe', 'ignore'] });
    return out.toString('utf8').split('\0').filter(Boolean).filter((f) => existsSync(join(ROOT, f)));
  } catch {
    return walk(ROOT); // 不是 git repo（例如被 cp 出去）→ 走檔案樹
  }
}

function isText(file) {
  const dot = file.lastIndexOf('.');
  const ext = dot === -1 ? '' : file.slice(dot).toLowerCase();
  if (!TEXT_EXT.has(ext)) return false;
  const size = statSync(join(ROOT, file)).size;
  return size <= 2 * 1024 * 1024;
}

const FILES = candidateFiles().filter(isText);

// 「一眼看得出是假的」：測試 fixture 只准長這樣（policy 寫在 CONTRIBUTING.md）
export function looksObviouslyFake(s) {
  const str = String(s);
  if (/EXAMPLE|FAKE|DUMMY|REDACTED|PLACEHOLDER|CHANGEME|YOUR[_-]?(KEY|TOKEN|SECRET)/i.test(str)) return true;
  if (/abcdef|ABCDEF|AbCdEf|aAbBcC|a1b2c3|0123456789|1234567890|xxxxxx|XXXXXX/i.test(str)) return true;
  // 只有 PEM 標頭、沒有 base64 內容（測試只驗標頭）
  if (/^-----BEGIN [A-Z ]+PRIVATE KEY-----\s*$/.test(str.trim())) return true;
  return false;
}

test('repo-hygiene：有候選檔案可掃（sanity）', () => {
  assert.ok(FILES.length > 20, `候選檔案太少（${FILES.length}），是不是路徑算錯了`);
  assert.ok(FILES.includes('main.mjs'));
});

test('repo-hygiene：所有會進版控的檔案（含文件/註解/測試）不得含真密鑰——命中 L1 規則的必須一眼是假的', () => {
  const offenders = [];
  for (const file of FILES) {
    const text = readFileSync(join(ROOT, file), 'utf8');
    for (const rule of SECRET_RULES) {
      const flags = rule.regex.flags.includes('g') ? rule.regex.flags : rule.regex.flags + 'g';
      const re = new RegExp(rule.regex.source, flags);
      for (const m of text.matchAll(re)) {
        const hit = m[0];
        if (looksObviouslyFake(hit)) continue;
        const line = text.slice(0, m.index).split('\n').length;
        offenders.push(`${file}:${line} [${rule.id}] ${hit.slice(0, 12)}…（長度 ${hit.length}）`);
      }
    }
  }
  assert.deepEqual(offenders, [], '疑似真密鑰（若是測試 fixture，請改成 EXAMPLE/FAKE/abcdef 這類一眼假的值）：\n' + offenders.join('\n'));
});

test('repo-hygiene：不得含私人絕對路徑（家目錄）與私人信箱', () => {
  // 用字串拼接避免本檔自己的 pattern 命中；<name> 這種佔位符（文件解釋政策用）放行
  const home = new RegExp('(/' + 'Users/[^/\\s`"\'<]+/|/' + 'home/[^/\\s`"\'<]+/|C:\\\\' + 'Users\\\\[^\\\\\\s<]+\\\\)');
  const email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  const offenders = [];
  for (const file of FILES) {
    const text = readFileSync(join(ROOT, file), 'utf8');
    text.split('\n').forEach((ln, i) => {
      if (home.test(ln)) offenders.push(`${file}:${i + 1} 私人絕對路徑：${ln.trim().slice(0, 100)}`);
      for (const m of ln.matchAll(email)) {
        const addr = m[0].toLowerCase();
        if (addr.endsWith('@example.com') || addr.startsWith('noreply@') || addr.endsWith('@users.noreply.github.com')) continue;
        if (ln.slice(0, m.index).includes('://')) continue; // URL 裡的 user:pass@host 不是信箱（密鑰形狀由上一個測試把關）
        offenders.push(`${file}:${i + 1} 信箱：${addr}`);
      }
    });
  }
  assert.deepEqual(offenders, [], offenders.join('\n'));
});

test('repo-hygiene：本機狀態/憑證檔一律 gitignore 且未被追蹤', () => {
  const gi = readFileSync(join(ROOT, '.gitignore'), 'utf8').split('\n').map((l) => l.trim());
  for (const f of ['.llm-token', '.dash-token', '.notify-state', '.llm-state', '.llm-scan-state', '.locale', 'panel.html.tmp']) {
    assert.ok(gi.includes(f), `.gitignore 缺 ${f}`);
    assert.ok(!FILES.includes(f), `${f} 不得進版控`);
  }
});

test('repo-hygiene：panel.html 只能是空資料模板（worker 會把真實 findings 烤進去，不得 commit 那個版本）', () => {
  if (!FILES.includes('panel.html')) return;
  const html = readFileSync(join(ROOT, 'panel.html'), 'utf8');
  const m = html.match(/window\.__VIBEGUARD_DATA__ \|\| (.*?);\n/);
  assert.ok(m, 'panel.html 不是本專案模板');
  const data = JSON.parse(m[1]);
  assert.deepEqual(data.groups, {}, 'panel.html 含真實 findings——提交前請還原成空模板');
  assert.deepEqual(data.scans ?? [], [], 'panel.html 含掃描記錄（有本機路徑）——提交前請還原成空模板');
  assert.ok(!('terminals' in data) || Object.keys(data.terminals).length === 0);
});

test('repo-hygiene：.vibeguard-learned.json 若進版控，target 必須是 repo 相對路徑', () => {
  if (!FILES.includes('.vibeguard-learned.json')) return;
  const entries = JSON.parse(readFileSync(join(ROOT, '.vibeguard-learned.json'), 'utf8'));
  for (const e of entries) assert.ok(!String(e.target).startsWith('/'), `learned 條目含絕對路徑：${e.target}`);
});
