// redaction.mjs — 送 LLM 前的脫敏（ISSUE-08）。
// 原則：送出去的字串必須完全不含真值（不是 maskSecret 的前4...後4）。

import { SECRET_RULES } from './l1-secrets.mjs';
import { ASSIGNMENT_RE } from './l1-entropy.mjs';

export const REDACTED = 'VIBEGUARD_REDACTED_SECRET';

/**
 * 脫敏：密鑰規則整段匹配替換；敏感賦值只替換「值」（group3），
 * 保留 `name = "VIBEGUARD_REDACTED_SECRET"` 結構讓 LLM 看得懂上下文。
 * @param {string} text
 * @returns {{ text: string, count: number }} count = 替換總次數
 */
export function redactForLlm(text) {
  if (typeof text !== 'string' || text.length === 0) return { text, count: 0 };
  let out = text;
  let count = 0;

  // 1. 密鑰規則：整段匹配替換
  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    out = out.replace(rule.regex, () => {
      count += 1;
      return REDACTED;
    });
  }

  // 2. 敏感賦值：只換值，保留 name = "..." 結構
  ASSIGNMENT_RE.lastIndex = 0;
  out = out.replace(ASSIGNMENT_RE, (whole, _name, quote, value) => {
    count += 1;
    // whole 結尾必為 value + 結尾引號；用位移精準切除，避免值含特殊字元時誤切
    return whole.slice(0, whole.length - 1 - value.length) + REDACTED + quote;
  });

  return { text: out, count };
}
