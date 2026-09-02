// L1 密鑰正則快篩（照 DeepSec rules/patterns.py SECRET_RULES，見 docs/02-deepsec-fidelity.md）。
// 純函式：不 import Orca API；IO 由呼叫方注入。

import { createFinding, maskSecret } from './finding.mjs';

// 11 條規則：id / regex 逐字照 DeepSec；message/suggestion 翻中文。
export const SECRET_RULES = [
  {
    id: 'hardcoded_secret_aws_access_key',
    regex: /\bA(?:KIA|SIA)[0-9A-Z]{16}\b/g,
    title: 'AWS Access Key 疑似被硬編碼',
    description: '偵測到符合 AWS Access Key ID 格式的常數。',
    suggestion: '移到 secret manager（如 AWS Secrets Manager）並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_github_token',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,255}\b/g,
    title: 'GitHub Token 疑似被硬編碼',
    description: '偵測到符合 GitHub personal access token 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該 token。',
  },
  {
    id: 'hardcoded_secret_slack_token',
    regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/g,
    title: 'Slack Token 疑似被硬編碼',
    description: '偵測到符合 Slack token 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該 token。',
  },
  {
    id: 'hardcoded_secret_stripe_key',
    regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    title: 'Stripe API Key 疑似被硬編碼',
    description: '偵測到符合 Stripe secret/restricted key 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_google_api_key',
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    title: 'Google API Key 疑似被硬編碼',
    description: '偵測到符合 Google API key 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_npm_token',
    regex: /\bnpm_[A-Za-z0-9]{36}\b/g,
    title: 'npm Token 疑似被硬編碼',
    description: '偵測到符合 npm access token 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該 token。',
  },
  {
    id: 'hardcoded_secret_anthropic_key',
    regex: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/g,
    title: 'Anthropic API Key 疑似被硬編碼',
    description: '偵測到符合 Anthropic API key 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_openai_key',
    regex: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}\b/g,
    title: 'OpenAI API Key 疑似被硬編碼',
    description: '偵測到符合 OpenAI API key 格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_jwt',
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    title: 'JWT Token 疑似被硬編碼',
    description: '偵測到符合 JWT（三段 base64url）格式的常數。',
    suggestion: '移到 secret manager 並撤銷輪換該 token。',
  },
  {
    id: 'hardcoded_secret_private_key',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |ED25519 )?PRIVATE KEY-----/g,
    title: 'Private Key 疑似被硬編碼',
    description: '偵測到 PEM private key block 標頭。',
    suggestion: '移到 secret manager 並撤銷輪換該金鑰。',
  },
  {
    id: 'hardcoded_secret_database_url',
    regex: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^:\s/@]+:[^@\s]+@[^)\s'"]+/gi,
    title: 'Database URL 疑似被硬編碼',
    description: '偵測到含密碼的資料庫連線字串。',
    suggestion: '移到 secret manager 並撤銷輪換該憑證。',
  },
];

// 照 DeepSec _position：line = offset 前 '\n' 數 + 1；column = offset - rfind('\n')（1-based）
export function indexToLineCol(text, offset) {
  const before = text.slice(0, offset);
  const line = (before.match(/\n/g) || []).length + 1;
  // lastIndexOf 從 offset-1 往回找，等同 Python rfind('\n', 0, offset)
  const lastNl = offset > 0 ? text.lastIndexOf('\n', offset - 1) : -1;
  const column = offset - lastNl; // lastNl=-1 → offset+1（1-based）
  return { line, column };
}

// 區間重疊判斷：[s1,e1) 與 [s2,e2)
function overlaps(s1, e1, s2, e2) {
  return s1 < e2 && s2 < e1;
}

/**
 * 掃描 text，回傳 Finding[]。
 * @param {string} text - 待掃描文字
 * @param {object} [opts]
 * @param {string|null} [opts.target=null] - 檔案路徑（寫入 finding.target）
 * @param {number[][]} [opts.seenRanges=[]] - 共享已命中範圍 [[start,end],...]；
 *   命中會 append，與已有範圍重疊的跳過（照 DeepSec seen_ranges）。
 */
export function scanSecrets(text, { target = null, seenRanges = [] } = {}) {
  const findings = [];

  for (const rule of SECRET_RULES) {
    // 重置 lastIndex（g flag regex 是 stateful）
    rule.regex.lastIndex = 0;
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;

      // 與 seenRanges 重疊 → 跳過（避免同值被多規則/多次掃描重複報告）
      if (seenRanges.some(([s, e]) => overlaps(start, end, s, e))) continue;

      seenRanges.push([start, end]);
      const { line, column } = indexToLineCol(text, start);
      const { line: endLine, column: endColumn } = indexToLineCol(text, end); // DeepSec _finding 也填 end 位置

      findings.push(
        createFinding({
          layer: 'L1',
          severity: 'critical',
          type: 'hardcoded_secret',
          rule: rule.id,
          title: rule.title,
          description: rule.description,
          evidence: maskSecret(m[0]),
          suggestion: rule.suggestion,
          line,
          column,
          endLine,
          endColumn,
          target,
        }),
      );
    }
  }

  return findings;
}
