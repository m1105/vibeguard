// L3 端點語意檢查（本地 regex 部分，照 DeepSec rules/ai_audit.py audit_semantics）。
// layer='L3'，confidence 固定 0.65，type 一律 'missing_security_measure'，evidence 一律 ''。
// LLM 語意審查部分在 l23-llm.mjs（ISSUE-08）。

import { createFinding } from './finding.mjs';
import { indexToLineCol } from './l1-secrets.mjs';

// 端點偵測 regex（逐字照 DeepSec _endpoints；[^^\n] 保留原作的雙 ^）
const PY_ENDPOINT_RE = /@(?:app|router|blueprint)\.(?:(get|post|put|patch|delete)|route)\s*\(\s*['"]([^'"]+)['"][^\n]*\)\s*\n(?:@[^^\n]+\n)*\s*(?:async\s+)?def\b[\s\S]{0,1800}/gi;
const JS_ENDPOINT_RE = /\b(?:app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`][\s\S]{0,1800}?\n\s*}\s*\)?\s*;?/gi;

// 關鍵字 regex（逐字，i flag）
const SENSITIVE_RE = /admin|account|billing|payment|profile|settings|user|token|secret|private/i;
const RATE_LIMIT_PATH_RE = /login|register|signup|password|reset|token|upload|invite/i;
const INPUT_RE = /\b(?:req\.(?:body|query|params)|request\.(?:json|form|args|GET|POST|body|FILES|headers)|body|query|params)\b/i;
const AUTH_RE = /authenticate|authorize|requireauth|isauthenticated|verifytoken|jwt|session|current_user|login_required|permission_required|bearer|preauthorize|secured/i;
const RATE_LIMIT_RE = /ratelimit|rate_limit|limiter|throttle|slowapi|express-rate-limit|@limit/i;
const VALIDATION_RE = /validate|validated|validator|schema|zod|joi|yup|pydantic|sanitize|escape|safeparse|basemodel|is_valid/i;
const IO_RE = /\b(?:fetch|axios|requests|httpx|query|execute|readfile|writefile|open|send_file|subprocess)\b/i;
const ERROR_HANDLING_RE = /\btry\s*(?:\{|:)|\bcatch\s*\(|\.catch\s*\(|\bexcept\b|error_?handler/i;

function endpoints(text, language) {
  const lang = typeof language === 'string' ? language.toLowerCase() : '';
  const pattern = lang === 'python' || lang === 'py' ? PY_ENDPOINT_RE : JS_ENDPOINT_RE;
  pattern.lastIndex = 0;
  const out = [];
  let m;
  while ((m = pattern.exec(text)) !== null) {
    out.push({ method: (m[1] || 'request').toLowerCase(), path: m[2], start: m.index, snippet: m[0] });
    if (m[0].length === 0) pattern.lastIndex += 1;
  }
  return out;
}

function makeFinding(target, text, start, severity, rule, description, suggestion) {
  const { line, column } = indexToLineCol(text, start);
  return createFinding({
    layer: 'L3',
    severity,
    type: 'missing_security_measure',
    rule,
    title: description,
    description,
    evidence: '',
    suggestion,
    line,
    column,
    confidence: 0.65,
    target,
  });
}

/**
 * 對每個端點做四條語意檢查（照 DeepSec audit_semantics）。
 * @param {string} text 檔案內容
 * @param {{ target?: string|null, language?: string|null }} [opts]
 * @returns {Array<object>} Finding[]
 */
export function auditSemantics(text, { target = null, language = null } = {}) {
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) return findings;

  for (const { method, path, start, snippet } of endpoints(text, language)) {
    const lower = snippet.toLowerCase();
    const mp = `${method.toUpperCase()} ${path}`;

    if (SENSITIVE_RE.test(path) && !AUTH_RE.test(lower)) {
      findings.push(makeFinding(target, text, start, 'high', 'l3_missing_authentication',
        `端點 ${mp} 疑似存取敏感功能但沒有明顯的認證。`, '暴露此端點前加上認證與授權。'));
    }
    if ((method !== 'get' || RATE_LIMIT_PATH_RE.test(path)) && !RATE_LIMIT_RE.test(lower)) {
      findings.push(makeFinding(target, text, start, 'medium', 'l3_missing_rate_limiting',
        `端點 ${mp} 疑似易被濫用且沒有明顯的限流。`, '依端點與身分加上合適的限流器。'));
    }
    if (INPUT_RE.test(lower) && !VALIDATION_RE.test(lower)) {
      findings.push(makeFinding(target, text, start, 'medium', 'l3_missing_input_validation',
        `端點 ${mp} 使用 request 輸入但沒有明顯的校驗。`, '使用前用明確的 schema 校驗 request 欄位。'));
    }
    if (INPUT_RE.test(lower) && IO_RE.test(lower) && !ERROR_HANDLING_RE.test(lower)) {
      findings.push(makeFinding(target, text, start, 'low', 'l3_missing_error_handling',
        `端點 ${mp} 有 IO 但沒有明顯的錯誤處理。`, '處理失敗並回傳安全的客戶端錯誤。'));
    }
  }

  return findings;
}
