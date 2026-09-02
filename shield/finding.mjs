// 統一 finding schema + 全域去重 + evidence 遮蔽。
// 數值規則逐字移植 DeepSec core/finding.py、rules/ai_audit.py coercion、dedup.py（見 docs/02-deepsec-fidelity.md）。

export const SEVERITIES = ['critical', 'high', 'medium', 'low'];
export const LAYER_RANK = { L1: 1, L2: 2, L3: 3 };

// ai_audit._coerce_confidence 字串對照表（trim+lower 後查表）
const CONFIDENCE_WORDS = {
  critical: 0.95, 'very high': 0.9, high: 0.85, medium: 0.6, moderate: 0.6,
  low: 0.35, 'very low': 0.2, info: 0.2, informational: 0.2, unknown: 0.6,
};

const clamp01 = (n) => Math.min(1, Math.max(0, n));

// 照 ai_audit._coerce_line：bool→null；整數/整數值 float→max(1,v)；字串→max(1,parseInt(parseFloat(trim))) 失敗→null
export function coerceLine(value) {
  if (typeof value === 'boolean') return null; // bool 先判（Python True is int，JS 需顯式排除）
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Number.isInteger(value) ? Math.max(1, value) : null; // 3.0 在 JS 即整數；3.7 → null
  }
  if (typeof value === 'string') {
    const n = parseInt(parseFloat(value.trim()), 10); // '3.7' → 3（截斷，與 Python int(float(v)) 一致）
    return Number.isNaN(n) ? null : Math.max(1, n);
  }
  return null;
}

// 照 ai_audit._coerce_confidence：數字 clamp（>1 不除 100）；字串查表，否則 parseFloat(去尾端%)，>1 除 100
export function coerceConfidence(value) {
  if (typeof value === 'boolean' || value === null || value === undefined) return 0.6;
  if (typeof value === 'number') {
    return Number.isFinite(value) ? clamp01(value) : 0.6; // NaN/Infinity 無意義，回預設
  }
  if (typeof value === 'string') {
    const s = value.trim().toLowerCase();
    if (s in CONFIDENCE_WORDS) return CONFIDENCE_WORDS[s];
    const n = parseFloat(s.replace(/%$/, '')); // '80%' → 80
    if (Number.isNaN(n)) return 0.6;
    return clamp01(n > 1 ? n / 100 : n); // 只有字串路徑才 >1 除 100
  }
  return 0.6;
}

// 照 patterns._redact：≤8 字元 → '***'；否則前4...後4
export function maskSecret(value) {
  const s = String(value);
  return s.length <= 8 ? '***' : s.slice(0, 4) + '...' + s.slice(-4);
}

// 統一 finding 形狀：欄位齊全，缺省值固定；severity/layer 白名單外回預設
export function createFinding(input = {}) {
  return {
    layer: LAYER_RANK[input.layer] ? input.layer : 'L1',
    severity: SEVERITIES.includes(input.severity) ? input.severity : 'medium', // 只接受小寫
    type: input.type ?? '',
    rule: input.rule ?? '',
    title: input.title ?? '',
    description: input.description ?? '',
    evidence: input.evidence ?? '',
    suggestion: input.suggestion ?? '',
    line: coerceLine(input.line),
    column: coerceLine(input.column),
    endLine: coerceLine(input.endLine),
    endColumn: coerceLine(input.endColumn),
    confidence: coerceConfidence(input.confidence), // 缺省 undefined → 0.6
    foundAt: input.foundAt ?? null, // 掃描到的时间（ISO），由 main.mjs 補上；vibeguard 擴充欄位
    worktreeId: input.worktreeId ?? null,
    agent: input.agent ?? null,
    target: input.target ?? null,
  };
}

// \u0000 分隔避免欄位值含分隔字元時碰撞
const keyOf = (...parts) => parts.join('\u0000');

// 全域去重（dedup.py unique_findings）+ 跨層合併：
// 1) (rule, target, line, evidence) 去重，保留第一筆
// 2) 同 (type, target, line) 不同 layer → 留 LAYER_RANK 最高者；同 rank 留先出現者
//    輸出順序 = 第一次出現的位置（勝出者原地取代）
export function uniqueFindings(findings) {
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const k = keyOf(f.rule, f.target, f.line, f.evidence);
    if (seen.has(k)) continue;
    seen.add(k);
    deduped.push(f);
  }

  const best = new Map(); // key -> { rank, pos }
  const result = [];
  for (const f of deduped) {
    const k = keyOf(f.type, f.target, f.line);
    const rank = LAYER_RANK[f.layer] ?? 0; // 未知 layer 視為最低
    const slot = best.get(k);
    if (!slot) {
      best.set(k, { rank, pos: result.length });
      result.push(f);
    } else if (rank > slot.rank) {
      result[slot.pos] = f; // 原地取代，維持第一次出現的順序
      slot.rank = rank;
    }
  }
  return result;
}

// ── finding 身分（不含行號）──
// agent 在檔案上方插幾行，全檔行號整體位移，但問題本身沒變。身分若含行號，
// 舊 finding 會整批被判「已修正」、新的整批掛 NEW，連 panel 的 meaningfulHash 都跟著變
// （面板反覆重烤重掛，使用者捲到一半被拉回頂端）。改用「命中行的內容」當指紋。
function fnv1a(s) {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i += 1) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

// 命中行的原始碼（snippet 裡 ln === line 那行）；沒有就退回 evidence
function hitText(finding) {
  const line = finding?.line;
  const snippet = Array.isArray(finding?.snippet) ? finding.snippet : null;
  if (snippet && Number.isInteger(line)) {
    const hit = snippet.find((s) => s?.ln === line);
    if (hit && typeof hit.text === 'string') return hit.text.trim();
  }
  if (typeof finding?.evidence === 'string') return finding.evidence.trim().slice(0, 200);
  return '';
}

export function fingerprint(finding) {
  return fnv1a(keyOf(finding?.rule ?? '', finding?.target ?? '', finding?.title ?? '', hitText(finding)));
}

// 同指紋多筆（例：同檔 6 個 ACAO 萬用字元）依行號順序給序號，整體位移後仍一一對應
export function assignIdentities(findings) {
  const seen = new Map();
  for (const finding of [...findings].sort((a, b) => (a?.line ?? 0) - (b?.line ?? 0))) {
    const k = fingerprint(finding);
    const n = seen.get(k) ?? 0;
    seen.set(k, n + 1);
    finding.identity = k + '#' + n;
  }
  return findings;
}

// 舊資料（storage 裡換版前寫的）沒有 identity 欄位 → 現算
export function identityOf(finding) {
  const id = finding?.identity;
  return typeof id === 'string' && id ? id : fingerprint(finding) + '#0';
}