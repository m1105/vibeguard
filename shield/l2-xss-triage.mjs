// l2-xss-triage.mjs — sast_xss_inner_html 的右值分析（VibeGuard 擴充，docs/02 #17）。純函式。
//
// DeepSec 的 regex 只認 DOMPurify/sanitize 開頭、且只看到換行為止 → 自訂跳脫函式（esc）、
// 純字面值三元、多行敘述全部報 high。dogfooding 實測單檔 13 筆 innerHTML 全是誤報。
// 這裡不改 regex（忠實度測試鎖著），改在命中後分析整個右值：
//   static  每個插入值都是字面值                         → 不報
//   escaped 每個動態部分都包在已知跳脫/數值函式裡         → 不報
//   builder 由 HTML 產生函式或 map().join() 組成          → medium（這行看不出來，請確認該函式有跳脫）
//   partial 有跳脫也有裸插值                             → medium（請確認沒跳脫的那幾個）
//   dynamic 沒看到任何跳脫 / 解析不了                    → high（DeepSec 原行為；寧可報不可漏）
// 同檔查證：右值是 fn(...) / .map(fn).join() / 區域變數時，到同一個檔找定義，分析每個 return
// 與每次賦值（遞迴 ≤3 層）；全部安全才算 escaped，找不到定義維持 builder/dynamic。
// 這不是 JS parser：看不懂就回 dynamic。

const LIT = '§'; // 字面值佔位符 §
const STATEMENT_MAX = 1200;

// 已知會讓輸出變安全的呼叫：HTML 跳脫 / 消毒 / 轉成數字或 URL 編碼
const ESCAPER_RE = /^(?:[\w$]+\.)*(?:esc|escape|escapeHtml|escapeHTML|escapeXml|htmlEscape|htmlEncode|encodeHTML|encodeHtml|sanitize\w*|purify|encodeURIComponent|encodeURI|Number|parseInt|parseFloat|String\s*\(\s*Number)\s*\(/;
const NUMERIC_TAIL_RE = /(?:\.length|\.(?:toFixed|toPrecision)\(\d*\))$/;
const BUILDER_CALL_RE = /^(?:[\w$]+\.)*(?:render\w*|\w*(?:Html|HTML|Markup|Template|Tpl))\s*\(/;
const MAP_JOIN_RE = /\.map\s*\(.*\)\s*\.join\s*\(.*\)$/s;

/** 從 start 起取一個敘述：到深度 0 的分號，或（無分號風格）下一行不是續接運算子為止。 */
export function statementFrom(text, start) {
  let depth = 0;
  let quote = null;
  let i = start;
  const limit = Math.min(text.length, start + STATEMENT_MAX);
  for (; i < limit; i += 1) {
    const ch = text[i];
    if (quote) {
      if (ch === '\\') i += 1;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') { if (depth === 0) break; depth -= 1; }
    else if (ch === ';' && depth === 0) break;
    else if (ch === '\n' && depth === 0) {
      const before = text.slice(start, i).trimEnd().slice(-1);
      const after = text.slice(i + 1, i + 200).trimStart()[0] ?? '';
      const continues = '+?:&|,(=.'.includes(before) || '+?:&|,).'.includes(after);
      if (!before || !continues) break;
    }
  }
  return text.slice(start, i).trimEnd();
}

// 字串字面值 → §；含 ${} 的 template literal → (§+expr+§…)，讓插值走同一套分類
function maskLiterals(src) {
  let out = '';
  for (let i = 0; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === "'" || ch === '"') {
      let j = i + 1;
      while (j < src.length && src[j] !== ch) j += src[j] === '\\' ? 2 : 1;
      if (j >= src.length) return null; // 未閉合
      out += LIT; i = j;
    } else if (ch === '`') {
      const parts = [LIT];
      let j = i + 1;
      for (; j < src.length && src[j] !== '`'; j += 1) {
        if (src[j] === '\\') { j += 1; continue; }
        if (src[j] === '$' && src[j + 1] === '{') {
          let depth = 1; let k = j + 2;
          for (; k < src.length && depth > 0; k += 1) { if (src[k] === '{') depth += 1; else if (src[k] === '}') depth -= 1; }
          if (depth !== 0) return null;
          const inner = maskLiterals(src.slice(j + 2, k - 1));
          if (inner == null) return null;
          parts.push('(' + inner + ')', LIT);
          j = k - 1;
        }
      }
      if (j >= src.length) return null;
      out += parts.length === 1 ? LIT : '(' + parts.join('+') + ')';
      i = j;
    } else if (ch === '/' && src[i + 1] === '/') {
      const nl = src.indexOf('\n', i); i = nl === -1 ? src.length : nl - 1;
    } else if (ch === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2); if (end === -1) return null; i = end + 1;
    } else out += ch;
  }
  return out;
}

// 深度 0 的切分（括號不平衡回 null）
function splitTop(s, sep) {
  const parts = []; let depth = 0; let last = 0;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) { depth -= 1; if (depth < 0) return null; }
    else if (ch === sep && depth === 0) { parts.push(s.slice(last, i)); last = i + 1; }
  }
  if (depth !== 0) return null;
  parts.push(s.slice(last));
  return parts;
}

function stripOuterParens(s) {
  let e = s.trim();
  while (e.startsWith('(') && e.endsWith(')')) {
    let depth = 0; let closesAtEnd = true;
    for (let i = 0; i < e.length; i += 1) {
      if (e[i] === '(') depth += 1;
      else if (e[i] === ')') { depth -= 1; if (depth === 0 && i < e.length - 1) { closesAtEnd = false; break; } }
    }
    if (!closesAtEnd) break;
    e = e.slice(1, -1).trim();
  }
  return e;
}

// 深度 0 的第一個三元 ?（排除 ?. 與 ??）與其配對的 :
function splitTernary(e) {
  let depth = 0; let q = -1; let nested = 0;
  for (let i = 0; i < e.length; i += 1) {
    const ch = e[i];
    if ('([{'.includes(ch)) depth += 1;
    else if (')]}'.includes(ch)) depth -= 1;
    else if (depth === 0 && ch === '?') {
      if (e[i + 1] === '.' || e[i + 1] === '?' || e[i - 1] === '?') continue;
      if (q === -1) q = i; else nested += 1;
    } else if (depth === 0 && ch === ':' && q !== -1) {
      if (nested === 0) return [e.slice(q + 1, i), e.slice(i + 1)];
      nested -= 1;
    }
  }
  return q === -1 ? null : undefined; // undefined = 有 ? 沒配到 : → 解析失敗
}

// 呼叫是否涵蓋整個運算元：name(...) 的右括號就是結尾
function callCoversAll(e, re) {
  const m = e.match(re);
  if (!m) return false;
  let depth = 0;
  for (let i = m[0].length - 1; i < e.length; i += 1) {
    if (e[i] === '(') depth += 1;
    else if (e[i] === ')') { depth -= 1; if (depth === 0) return i === e.length - 1; }
  }
  return false;
}

const RANK = ['static', 'escaped', 'builder', 'partial', 'dynamic'];
function combine(kinds) {
  if (kinds.includes('partial')) return 'partial';
  const hasDynamic = kinds.includes('dynamic');
  if (hasDynamic) return kinds.includes('escaped') ? 'partial' : 'dynamic';
  return RANK[Math.max(...kinds.map((k) => RANK.indexOf(k)))];
}

// ── 同檔查證：右值是函式呼叫 / 區域變數時，到同一個檔找定義再分類 ──
const MAX_DEPTH = 3;
const IDENT_RE = /^[A-Za-z_$][\w$]*$/;
const CALL_NAME_RE = /^([A-Za-z_$][\w$]*)\s*\(/;
const MAP_FN_JOIN_RE = /\.map\s*\(\s*([A-Za-z_$][\w$]*)\s*\)\s*\.join\s*\(.*\)$/s;

// 從 openIdx 的 { 取到配對的 }（跳過字串與註解）；不平衡回 null
function extractBlock(text, openIdx) {
  let depth = 0; let quote = null;
  for (let i = openIdx; i < text.length && i < openIdx + 20000; i += 1) {
    const ch = text[i];
    if (quote) { if (ch === '\\') i += 1; else if (ch === quote) quote = null; continue; }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }
    if (ch === '/' && text[i + 1] === '/') { const nl = text.indexOf('\n', i); if (nl === -1) return null; i = nl; continue; }
    if (ch === '/' && text[i + 1] === '*') { const end = text.indexOf('*/', i + 2); if (end === -1) return null; i = end + 1; continue; }
    if (ch === '{') depth += 1;
    else if (ch === '}') { depth -= 1; if (depth === 0) return text.slice(openIdx + 1, i); }
  }
  return null;
}

// 找 function name(...) { … } / name = function(...) { … } / name = (...) => { … } 的函式本體
function findFunctionBody(text, name) {
  const n = name.split('$').join('\\$');
  const re = new RegExp('(?:function\\s+' + n + '\\s*\\(|(?:const|let|var)\\s+' + n + '\\s*=\\s*(?:async\\s*)?(?:function\\b[^(]*)?\\()');
  const m = re.exec(text);
  if (!m) return null;
  let depth = 1; let i = m.index + m[0].length;
  for (; i < text.length && depth > 0; i += 1) { if (text[i] === '(') depth += 1; else if (text[i] === ')') depth -= 1; }
  if (depth !== 0) return null;
  const rest = text.slice(i, i + 80);
  const open = rest.match(/^\s*(?::[^={]+)?(?:=>)?\s*\{/);
  if (open) return extractBlock(text, i + open[0].length - 1);
  const arrow = rest.match(/^\s*=>\s*/);
  return arrow ? 'return ' + statementFrom(text, i + arrow[0].length) + ';' : null;
}

function resolveFunction(name, ctx) {
  if (!ctx.text || ctx.depth >= MAX_DEPTH || ctx.stack.has(name)) return null;
  const body = findFunctionBody(ctx.text, name);
  if (body == null) return null;
  const inner = { text: ctx.text, scope: body, depth: ctx.depth + 1, stack: new Set([...ctx.stack, name]) };
  const kinds = [];
  const re = /\breturn\b/g;
  let m;
  while ((m = re.exec(body)) !== null) {
    const expr = statementFrom(body, m.index + 6).trim();
    if (expr) kinds.push(classifyRaw(expr, inner));
  }
  if (!kinds.length) return null;
  const k = combine(kinds);
  return k === 'static' ? 'escaped' : k;
}

// 區域變數：收集 scope 內對它的所有賦值（= 與 +=），全部分類後合併
function resolveIdentifier(name, ctx) {
  if (!ctx.scope || ctx.depth >= MAX_DEPTH || ctx.stack.has('$' + name)) return null;
  const n = name.split('$').join('\\$');
  const re = new RegExp('(?:^|[^\\w$.])' + n + '\\s*\\+?=(?!=)\\s*', 'g');
  const inner = { ...ctx, depth: ctx.depth + 1, stack: new Set([...ctx.stack, '$' + name]) };
  const kinds = [];
  let m;
  while ((m = re.exec(ctx.scope)) !== null) {
    const raw = statementFrom(ctx.scope, m.index + m[0].length);
    const masked = maskLiterals(raw);
    if (masked == null) return null;
    const first = splitTop(masked, ','); // var a=…, b=… 只取自己的宣告
    kinds.push(first ? classifyMasked(first[0], inner) : 'dynamic');
  }
  return kinds.length ? combine(kinds) : null;
}

function classifyRaw(raw, ctx) {
  const masked = maskLiterals(raw);
  return masked == null ? 'dynamic' : classifyMasked(masked, ctx);
}

function classifyMasked(expr, ctx) {
  const e = stripOuterParens(expr);
  if (e === '') return 'dynamic';
  if (e === LIT || /^-?\d+(?:\.\d+)?$/.test(e)) return 'static';
  const tern = splitTernary(e);
  if (tern === undefined) return 'dynamic';
  if (tern) return combine(tern.map((x) => classifyMasked(x, ctx))); // 條件不進輸出，只看兩支
  const sum = splitTop(e, '+');
  if (sum == null) return 'dynamic';
  if (sum.length > 1) return combine(sum.map((x) => classifyMasked(x, ctx)));
  if (callCoversAll(e, ESCAPER_RE) || NUMERIC_TAIL_RE.test(e)) return 'escaped';
  const mapFn = e.match(MAP_FN_JOIN_RE);
  if (mapFn) return resolveFunction(mapFn[1], ctx) ?? 'builder';
  if (MAP_JOIN_RE.test(e)) return 'builder';
  const call = callCoversAll(e, CALL_NAME_RE) ? e.match(CALL_NAME_RE)[1] : null;
  if (call) { const k = resolveFunction(call, ctx); if (k) return k; }
  if (callCoversAll(e, BUILDER_CALL_RE)) return 'builder';
  if (IDENT_RE.test(e)) return resolveIdentifier(e, ctx) ?? 'dynamic';
  return 'dynamic';
}

/** 右值分類：'static' | 'escaped' | 'builder' | 'partial' | 'dynamic'（看不懂一律 dynamic） */
export function classifyHtmlExpr(rhs, { text = '', scope = '' } = {}) {
  if (typeof rhs !== 'string' || !rhs.trim()) return 'dynamic';
  try { return classifyRaw(rhs, { text, scope, depth: 0, stack: new Set() }); } catch { return 'dynamic'; }
}

/**
 * @param {string} text 整份檔案
 * @param {number} matchIndex sast_xss_inner_html 命中起點（`.innerHTML` 的那個點）
 * @returns {{ level: 'skip'|'medium'|'high', kind: string }}
 */
export function triageInnerHtml(text, matchIndex) {
  const stmt = statementFrom(text, matchIndex);
  const eq = stmt.indexOf('=');
  // scope：命中點之前的一段，用來解析區域變數（var html = …; el.innerHTML = html）
  const scope = text.slice(Math.max(0, matchIndex - 6000), matchIndex);
  const kind = eq === -1 ? 'dynamic' : classifyHtmlExpr(stmt.slice(eq + 1), { text, scope });
  if (kind === 'static' || kind === 'escaped') return { level: 'skip', kind };
  if (kind === 'builder' || kind === 'partial') return { level: 'medium', kind };
  return { level: 'high', kind };
}
