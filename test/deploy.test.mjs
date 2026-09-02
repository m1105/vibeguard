// deploy.test.mjs — 部署清單自檢：scripts/deploy.mjs 的 INCLUDE 必須涵蓋 main.mjs 的所有（遞移）相對 import。
// 為什麼：漏檔的部署會讓 worker import 秒死 → host 連續重啟 3 次 → 插件標 errored（實際發生過：漏 dashboard.mjs）。
// deploy.mjs 跑完有載入自檢，但那是事後；這裡在 npm test 就擋。

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));

function includeList() {
  const src = readFileSync(join(ROOT, 'scripts', 'deploy.mjs'), 'utf8');
  const m = src.match(/const INCLUDE = (\[[^\]]*\]);/);
  assert.ok(m, 'deploy.mjs 找不到 const INCLUDE = [...]');
  return JSON.parse(m[1].replace(/'/g, '"'));
}

// 從 main.mjs 出發，遞移蒐集所有相對 import（'./x.mjs' / './shield/y.mjs'）
function relativeImportsFrom(entry) {
  const seen = new Set();
  const queue = [resolve(ROOT, entry)];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, 'utf8');
    for (const m of src.matchAll(/(?:import|from)\s+['"](\.{1,2}\/[^'"]+)['"]/g)) {
      queue.push(resolve(dirname(file), m[1]));
    }
  }
  seen.delete(resolve(ROOT, entry));
  return [...seen].map((f) => f.slice(ROOT.length + 1));
}

test('deploy INCLUDE 涵蓋 main.mjs 的全部遞移相對 import（漏檔 = worker 秒死 3 次標 errored）', () => {
  const include = includeList();
  const deps = relativeImportsFrom('main.mjs');
  assert.ok(deps.length >= 10, `import 圖太小（${deps.length}），解析可能失敗`);
  const missing = deps.filter((rel) => {
    const top = rel.split('/')[0];
    return !include.includes(rel) && !include.includes(top);
  });
  assert.deepEqual(missing, [], 'deploy.mjs 的 INCLUDE 漏了：' + missing.join(', '));
  for (const rel of deps) assert.ok(existsSync(join(ROOT, rel)), `import 指向不存在的檔：${rel}`);
});

test('deploy INCLUDE 含 manifest 與 package.json；manifest 的 main 與 panel entry 都有對應處理', () => {
  const include = includeList();
  assert.ok(include.includes('orca-plugin.json'));
  assert.ok(include.includes('package.json'));
  const manifest = JSON.parse(readFileSync(join(ROOT, 'orca-plugin.json'), 'utf8'));
  assert.ok(include.includes(manifest.main), `manifest.main=${manifest.main} 不在 INCLUDE`);
  const deploySrc = readFileSync(join(ROOT, 'scripts', 'deploy.mjs'), 'utf8');
  for (const p of manifest.contributes.panels) {
    assert.ok(include.includes(p.entry) || deploySrc.includes(p.entry), `panel entry ${p.entry} 沒被 deploy 處理`);
  }
});

test('manifest 與 package.json 版本一致；i18n 字典檔在 INCLUDE（面板/通知都靠它）', () => {
  const manifest = JSON.parse(readFileSync(join(ROOT, 'orca-plugin.json'), 'utf8'));
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(manifest.version, pkg.version, 'orca-plugin.json 與 package.json 版本要同步');
  assert.ok(includeList().includes('i18n.mjs'));
});
