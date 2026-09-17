// L1 熵分析：偵測敏感變數被賦予高熵字面值（疑似硬編碼密鑰）。
// 純函式，不 import Orca API。逐字照 DeepSec patterns.py（見 docs/02-deepsec-fidelity.md #2–#7）。
import { createFinding, maskSecret } from './finding.mjs';
import { indexToLineCol } from './l1-secrets.mjs';

// Shannon 熵：-Σ(p·log2 p)，p = charCount/length。空字串 → 0。
export function shannonEntropy(s) {
  if (s.length === 0) return 0;
  const freq = new Map();
  for (const ch of s) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// 高熵判定（逐字照 DeepSec _high_entropy）。
export function isHighEntropy(value, contextual = true) {
  if (/\s/.test(value)) return false; // 含空白 → 否
  if (!/[A-Za-z]/.test(value)) return false; // 無字母 → 否
  if (!/\d/.test(value)) return false; // 無數字 → 否

  const len = value.length;
  if (contextual) {
    // contextual=true：長度 16–180，熵 ≥ 3.8
    if (len < 16 || len > 180) return false;
    return shannonEntropy(value) >= 3.8;
  }
  // contextual=false：長度 24–180，熵 ≥ 4.5（DeepSec 兩種模式都擋 >180）
  if (len < 24 || len > 180) return false;
  return shannonEntropy(value) >= 4.5;
}

// Placeholder 集合（逐字照 DeepSec _placeholder）。
const PLACEHOLDERS = new Set([
  'changeme', 'change-me', 'example', 'sample', 'placeholder',
  'your-key', 'your-api-key', 'your-secret', 'your-token',
  'test', 'test-key', 'dummy', 'fake', 'todo',
]);

function isPlaceholder(value) {
  return PLACEHOLDERS.has(value.trim().toLowerCase().replaceAll(' ', '-'));
}

// 環境變數引用（逐字照 DeepSec _environment_reference）：整行命中即跳過。
const ENV_REF_RE = new RegExp('(?:process\\.env|os\\.getenv|os\\.environ|import\\.meta\\.env|ENV\\[)');

// 敏感賦值 regex（i flag，逐字照 DeepSec _sensitive_assignments）。
// group1=變數名, group2=引號, group3=值（≥6 字元）
// export 供 redaction.mjs 重用（ISSUE-08）
export const ASSIGNMENT_RE = /\b([A-Za-z_][A-Za-z0-9_]*(?:api[_-]?key|secret|password|passwd|pwd|token|private[_-]?key|jwt[_-]?secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|credential)[A-Za-z0-9_]*)\b\s*[:=]\s*(['"`])((?:\\.|(?!\2).){6,})\2/gi;

// ── VibeGuard 偏離 DeepSec（docs/02 #16）：非高熵值的「形狀分流」──
// DeepSec 對任何非 placeholder 的值一律報 critical，實測 dogfooding 誤報成災：
// "pay_corp:open"（callback 前綴）、regex 字面值、識別字（…_ID / …_PREFIX）、註解裡的範例全被當密鑰。
// 高熵路徑不動；非高熵值依形狀分三級：skip（明顯不是密鑰）/ low（像識別字或範例）/ critical（DeepSec 原行為）。
const NON_SECRET_VALUE_RE = /[\s|\\*?^$()[\]{}<>]|[^\x20-\x7e]/; // 空白、regex/glob 中繼字元、非 ASCII → pattern 或文案
// 變數名尾巴是「名字類」後綴 → 值是某個東西的名稱/前綴/雜湊，不是憑證本身。
// 刻意不含 key（api_key 的 key 是敏感核心字）。
const IDENTIFIER_SUFFIX_RE = /(?:^|[_-])?(?:id|ids|name|names|prefix|suffix|type|kind|label|header|field|path|url|env|var|param|flag|mode|scope|hash|length|len|ttl|format|regex|pattern|rehash)$/i;
const COMMENT_LINE_RE = /^\s*(?:\/\/|\/\*|\*|#|--|<!--|;)/;

/**
 * 非高熵值的分流。回 { level: 'skip' | 'low' | 'critical', reason?: string }
 * @param {{ varName: string, value: string, line: string }} input
 */
export function triageLowEntropyAssignment({ varName, value, line }) {
  if (NON_SECRET_VALUE_RE.test(value)) return { level: 'skip', reason: 'pattern-or-text' };
  if (IDENTIFIER_SUFFIX_RE.test(varName)) return { level: 'skip', reason: 'identifier-name' };
  if (COMMENT_LINE_RE.test(line)) return { level: 'low', reason: 'comment' };
  if (!/\d/.test(value)) return { level: 'low', reason: 'no-digit' };
  return { level: 'critical' };
}

const LOW_REASON_TEXT = {
  comment: '命中行是註解，多半是文件範例',
  'no-digit': '值無數字、像識別字或單字',
};

/**
 * 掃描 text，回報敏感變數被賦予字面值的 finding。
 * @param {string} text - 檔案內容
 * @param {{ target?: string|null, seenRanges?: Array<[number,number]> }} [opts]
 * @returns {Array<object>} findings（severity 一律 critical）
 */
export function scanEntropy(text, { target = null, seenRanges = [] } = {}) {
  const findings = [];

  ASSIGNMENT_RE.lastIndex = 0;
  let m;
  while ((m = ASSIGNMENT_RE.exec(text)) !== null) {
    const varName = m[1];
    const rawValue = m[3];
    const value = rawValue.trim(); // DeepSec: group3 先 strip，placeholder/熵/evidence 都用 strip 後的值

    // 值的 [start, end) range（不含引號；用未 strip 的 group3 位移，等同 DeepSec match.start/end(3)）
    const valueEnd = m.index + m[0].length - 1; // closing quote position
    const valueStart = valueEnd - rawValue.length;

    // 1. placeholder → 跳過
    if (isPlaceholder(value)) continue;

    // 2. 整行含環境變數引用 → 跳過
    const lineStart = text.lastIndexOf('\n', m.index - 1) + 1;
    let lineEnd = text.indexOf('\n', m.index);
    if (lineEnd === -1) lineEnd = text.length;
    const line = text.slice(lineStart, lineEnd);
    if (ENV_REF_RE.test(line)) continue;

    // 3. 與 seenRanges 重疊 → 跳過
    if (seenRanges.some(([s, e]) => valueStart < e && s < valueEnd)) continue;

    // 註冊此 range
    seenRanges.push([valueStart, valueEnd]);

    const { line: ln, column } = indexToLineCol(text, m.index);
    const matchEnd = m.index + m[0].length; // DeepSec _finding 用 match.end() 定位 end 位置
    const { line: endLn, column: endCol } = indexToLineCol(text, matchEnd);
    const highEntropy = isHighEntropy(value, true);
    // 4. 非高熵值依形狀分流（VibeGuard 擴充，docs/02 #16）
    const triage = highEntropy ? { level: 'critical' } : triageLowEntropyAssignment({ varName, value, line });
    if (triage.level === 'skip') continue;
    const low = triage.level === 'low';

    findings.push(
      createFinding({
        layer: 'L1',
        severity: low ? 'low' : 'critical',
        type: 'hardcoded_secret',
        rule: highEntropy ? 'hardcoded_secret_high_entropy_assignment' : 'hardcoded_secret_assignment',
        title: highEntropy ? '敏感變數被賦予高熵字面值' : (low ? '敏感變數被賦予字面值（低風險）' : '敏感變數被賦予字面值'),
        description: low
          ? `變數 ${varName} 被賦予字面值，但${LOW_REASON_TEXT[triage.reason]}，多半不是真密鑰——請看一眼確認。`
          : `變數 ${varName} 被賦予疑似密鑰的字面值。`,
        evidence: `${varName} = ${maskSecret(value)}`,
        suggestion: low ? '若確實不是密鑰，按「忽略這筆」即可；是密鑰就改用環境變數或 secret manager。' : '改用環境變數或 secret manager。',
        ...(low ? { confidence: 0.3 } : {}),
        line: ln,
        column,
        endLine: endLn,
        endColumn: endCol,
        target,
      })
    );
  }

  return findings;
}
