import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyHtmlExpr, statementFrom, triageInnerHtml } from '../shield/l2-xss-triage.mjs';
import { scanSast } from '../shield/l2-sast.mjs';

// VibeGuard 偏離 DeepSec（docs/02 #17）：sast_xss_inner_html 只認 DOMPurify/sanitize 開頭、只看到換行為止，
// 自訂跳脫函式（esc）、純字面值三元、多行敘述全部報 high——dogfooding 實測一個檔 13 筆全是誤報。

test('classifyHtmlExpr: 純字面值 / 字面值拼接 / 三元兩支都是字面值 → static', () => {
  assert.equal(classifyHtmlExpr(`'<b>hi</b>'`), 'static');
  assert.equal(classifyHtmlExpr(`'<b>' + "x" + \`y\``), 'static');
  assert.equal(classifyHtmlExpr(`rangeOpen?'&#9652;':'&#9662;'`), 'static');
  assert.equal(classifyHtmlExpr(`(a && b) ? '<i>1</i>' : (c ? '' : '<i>2</i>')`), 'static');
  assert.equal(classifyHtmlExpr(`'<td>' + 3 + '</td>'`), 'static');
});

test('classifyHtmlExpr: 每個動態部分都包在跳脫函式裡 → escaped', () => {
  assert.equal(classifyHtmlExpr(`'<div class="msg">'+esc(COPY.loading)+'</div>'`), 'escaped');
  assert.equal(classifyHtmlExpr(`(slot==='acctCurrent'?esc(COPY.acctCurrent)+': ':'')\n      +(head?esc(head)+' · ':'')`), 'escaped');
  assert.equal(classifyHtmlExpr(`escapeHtml(name) + '<br>' + _.escape(bio)`), 'escaped');
  assert.equal(classifyHtmlExpr(`DOMPurify.sanitize(html)`), 'escaped');
  assert.equal(classifyHtmlExpr('`<b>${esc(name)}</b> ${encodeURIComponent(q)}`'), 'escaped');
  assert.equal(classifyHtmlExpr(`'<td>' + Number(n) + '</td><td>' + amount.toFixed(2) + '</td><td>' + rows.length + '</td>'`), 'escaped');
});

test('classifyHtmlExpr: HTML 產生函式 / map-join → builder（無法從這行判斷，但不是裸插值）', () => {
  assert.equal(classifyHtmlExpr(`v.rows.map(txRowHtml).join('')`), 'builder');
  assert.equal(classifyHtmlExpr(`v.rows.length\n      ? v.rows.map(txRowHtml).join('')\n      : '<div class="empty">'+esc(emptyText)+'</div>'`), 'builder');
  assert.equal(classifyHtmlExpr(`renderRow(item) + '<hr>'`), 'builder');
});

test('classifyHtmlExpr: 有跳脫也有裸插值 → partial；完全沒跳脫 → dynamic', () => {
  assert.equal(classifyHtmlExpr(`'<b>'+esc(a)+'</b>'+b`), 'partial');
  assert.equal(classifyHtmlExpr('`<b>${esc(a)}</b>${b}`'), 'partial');
  assert.equal(classifyHtmlExpr(`userInput`), 'dynamic');
  assert.equal(classifyHtmlExpr(`'<b>' + req.query.name + '</b>'`), 'dynamic');
  assert.equal(classifyHtmlExpr('`<p>${comment}</p>`'), 'dynamic');
  // 名字裡有 esc 但不是呼叫、或跳脫函式只包一部分 → 不算
  assert.equal(classifyHtmlExpr(`description`), 'dynamic');
  assert.equal(classifyHtmlExpr(`esc(a) + b`), 'partial');
});

test('classifyHtmlExpr: 解析不了的怪東西一律 dynamic（寧可報，不可漏）', () => {
  assert.equal(classifyHtmlExpr(`foo(`), 'dynamic');
  assert.equal(classifyHtmlExpr(''), 'dynamic');
  assert.equal(classifyHtmlExpr(`cond ? a`), 'dynamic');
});

test('statementFrom: 抓到分號或敘述結束為止（跨行續接），上限保護', () => {
  const src = `el.innerHTML=(a?esc(x)+': ':'')\n      +(head?esc(head)+' · ':'')\n      +'<b>'+esc(z)+'</b>';\nnext();`;
  assert.ok(statementFrom(src, 0).endsWith(`'</b>'`));
  // 無分號風格：下一行不是續接運算子就停
  assert.equal(statementFrom(`a.innerHTML = x\nfoo()`, 0), 'a.innerHTML = x');
  // 字串裡的分號不算
  assert.equal(statementFrom(`a.innerHTML = 'a;b' + c;`, 0), `a.innerHTML = 'a;b' + c`);
  assert.ok(statementFrom('x = ' + 'a+'.repeat(2000), 0).length <= 1200);
});

test('triageInnerHtml: static/escaped → skip；builder/partial → medium+說明；dynamic → high 照舊', () => {
  assert.deepEqual(triageInnerHtml(`$('x').innerHTML=rangeOpen?'&#9652;':'&#9662;';`, 0), { level: 'skip', kind: 'static' });
  assert.deepEqual(triageInnerHtml(`$('m').innerHTML='<div>'+esc(t)+'</div>';`, 0), { level: 'skip', kind: 'escaped' });
  assert.equal(triageInnerHtml(`l.innerHTML=rows.map(rowHtml).join('');`, 0).level, 'medium');
  assert.equal(triageInnerHtml(`l.innerHTML='<b>'+esc(a)+'</b>'+b;`, 0).kind, 'partial');
  assert.deepEqual(triageInnerHtml(`el.innerHTML = userInput;`, 0), { level: 'high', kind: 'dynamic' });
});

test('scanSast 整合：使用者回報的 driver-wallet 形狀——靜態與全跳脫不報，builder 降 medium，裸插值仍 high', () => {
  const src = [
    `$('rangeCaret').innerHTML=rangeOpen?'&#9652;':'&#9662;';`,
    `$('txnList').innerHTML=v.rows.length`,
    `  ? v.rows.map(txRowHtml).join('')`,
    `  : '<div class="empty">'+esc(emptyText)+'</div>';`,
    `el.innerHTML=(slot==='acctCurrent'?esc(COPY.acctCurrent)+': ':'')`,
    `  +(head?esc(head)+' · ':'');`,
    `$('modalBody').innerHTML='<div class="msg">'+esc(COPY.loading)+'</div>';`,
    `out.innerHTML = '<p>' + req.query.q + '</p>';`,
  ].join('\n');
  const hits = scanSast(src).filter((f) => f.rule === 'sast_xss_inner_html');
  assert.deepEqual(hits.map((f) => [f.line, f.severity]), [[2, 'medium'], [8, 'high']]);
  const builder = hits[0];
  assert.equal(builder.confidence, 0.4);
  assert.ok(builder.title.includes('待確認'), builder.title);
  assert.ok(builder.description.includes('產生函式'), builder.description);
  assert.equal(hits[1].confidence, 0.6, '裸插值維持 DeepSec 原行為');
});

// ── 同檔查證：右值是函式呼叫 → 找同檔定義，分析每個 return（含區域變數、遞迴）──
const PAGE = [
  `function esc(s){ return String(s).replace(/[&<>]/g, function(c){ return c; }); }`,
  `function wdLine(label,value){`,
  `  return '<div class="ln"><span>'+esc(label)+'</span><span>'+esc(value)+'</span></div>';`,
  `}`,
  `function copyRow(id,label,value){`,
  `  if(!value) return '';`,
  `  return '<div>'+esc(label)+'</div>'+'<button data-v="'+esc(id)+'">'+esc(COPY.copy)+'</button>';`,
  `}`,
  `function txRightHtml(row){ return row.ok ? '<i>'+esc(row.t)+'</i>' : ''; }`,
  `function txRowHtml(row){`,
  `  var cls=(row.minus)?'minus':'plus';`,
  `  var code=row.orderCode?('<span>'+esc(row.orderCode)+'</span>'):'';`,
  `  return '<div class="'+cls+'">'+code+esc(row.amountText)+txRightHtml(row)+'</div>';`,
  `}`,
  `function rawRow(row){ return '<td>'+row.name+'</td>'; }`,
  `function halfRow(row){ return '<td>'+esc(row.a)+'</td><td>'+row.b+'</td>'; }`,
].join('\n');

test('同檔查證：產生函式每個 return 都跳脫 → escaped（不報）；含區域變數與巢狀產生函式', () => {
  assert.equal(classifyHtmlExpr(`wdLine(COPY.s, t(row))`, { text: PAGE }), 'escaped');
  assert.equal(classifyHtmlExpr(`copyRow('a',L.a,x)\n  +copyRow('b',L.b,y)`, { text: PAGE }), 'escaped');
  assert.equal(classifyHtmlExpr(`v.rows.map(txRowHtml).join('')`, { text: PAGE }), 'escaped');
  assert.equal(classifyHtmlExpr(`v.rows.length ? v.rows.map(txRowHtml).join('') : '<p>'+esc(e)+'</p>'`, { text: PAGE }), 'escaped');
});

test('同檔查證：產生函式內有裸插值 → dynamic / partial（照報）；找不到定義 → builder', () => {
  assert.equal(classifyHtmlExpr(`rows.map(rawRow).join('')`, { text: PAGE }), 'dynamic');
  assert.equal(classifyHtmlExpr(`halfRow(r)`, { text: PAGE }), 'partial');
  assert.equal(classifyHtmlExpr(`rows.map(unknownRowHtml).join('')`, { text: PAGE }), 'builder');
  assert.equal(classifyHtmlExpr(`mystery(r)`, { text: PAGE }), 'dynamic', '不認得名字又找不到定義 → 照舊');
});

test('同檔查證：遞迴自我呼叫不會無限迴圈', () => {
  const loop = `function a(x){ return '<b>'+a(x)+'</b>'; }`;
  assert.ok(['dynamic', 'builder', 'partial'].includes(classifyHtmlExpr(`a(1)`, { text: loop })));
});

test('scanSast 整合：同檔有安全的產生函式 → 多行 copyRow(...) 不報；rawRow 仍 high', () => {
  const src = PAGE + `\n$('m').innerHTML=\n  copyRow('a',L.a,x)\n  +copyRow('b',L.b,y);\n$('n').innerHTML=rows.map(rawRow).join('');\n`;
  const hits = scanSast(src).filter((f) => f.rule === 'sast_xss_inner_html');
  assert.deepEqual(hits.map((f) => f.severity), ['high']);
  assert.ok(hits[0].evidence.includes('rawRow'));
});
