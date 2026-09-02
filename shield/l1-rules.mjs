// L1 規則掃描：CONFIG_RULES（13）+ AI_PATTERN_RULES（20）。
// id / severity / languages / 正則逐字照 DeepSec rules/patterns.py（見 docs/02、issues/ISSUE-04）。
// title/description/suggestion 翻中文；evidence 用原文（DeepSec 對這兩層 redact=False，不遮蔽）。
// 不用 seenRanges（DeepSec scan_patterns 對這兩層傳 None）；跨規則去重由 scanner 全域 dedup 處理。

import { createFinding } from './finding.mjs';
import { indexToLineCol } from './l1-secrets.mjs';

// ── CONFIG_RULES（13）type='insecure_config' ────────────────
export const CONFIG_RULES = [
  { type: 'insecure_config', id: 'insecure_config_debug_true', severity: 'high', languages: ['python'], regex: /\bDEBUG\s*=\s*True\b/g,
    title: '除錯模式已啟用', description: 'Django 或 Flask 的 debug 模式被開啟。', suggestion: '正式環境請關閉 debug 模式。' },
  { type: 'insecure_config', id: 'insecure_config_app_debug_true', severity: 'high', languages: [], regex: /\bapp\.debug\s*=\s*(?:True|true)\b/g,
    title: '應用程式除錯模式已啟用', description: 'app.debug 被設為 True。', suggestion: '正式環境請關閉 debug 模式。' },
  { type: 'insecure_config', id: 'insecure_config_allowed_hosts_wildcard', severity: 'high', languages: ['python'], regex: /\bALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/g,
    title: 'ALLOWED_HOSTS 允許所有主機', description: 'Django ALLOWED_HOSTS 設為萬用字元。', suggestion: '填正式環境的明確主機名稱。' },
  { type: 'insecure_config', id: 'insecure_config_cors_allow_all', severity: 'high', languages: ['python'], regex: /\b(?:CORS_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\s*=\s*True\b/g,
    title: 'CORS 允許所有來源', description: 'CORS 設定為允許任意 origin。', suggestion: '限制 CORS 只允許信任的來源。' },
  { type: 'insecure_config', id: 'insecure_config_acao_wildcard', severity: 'medium', languages: [], regex: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/gi,
    title: 'Access-Control-Allow-Origin 為萬用字元', description: '回應標頭允許任意 origin。', suggestion: '回傳白名單內的特定 origin。' },
  { type: 'insecure_config', id: 'insecure_config_disable_host_check', severity: 'high', languages: [], regex: /\bDANGEROUSLY_DISABLE_HOST_CHECK\s*=\s*(?:true|1)\b/gi,
    title: 'Host 標頭檢查被停用', description: 'DANGEROUSLY_DISABLE_HOST_CHECK 被開啟。', suggestion: '設定明確的信任主機清單。' },
  { type: 'insecure_config', id: 'insecure_config_csrf_exempt', severity: 'high', languages: ['python'], regex: /@csrf_exempt\b|\bcsrf_exempt\s*\(/g,
    title: '端點停用了 CSRF 防護', description: '使用 @csrf_exempt 關閉 CSRF 檢查。', suggestion: '保持 CSRF 防護啟用，或加嚴格審查過的替代控制。' },
  { type: 'insecure_config', id: 'insecure_config_spring_permit_all', severity: 'medium', languages: ['java'], regex: /\.permitAll\s*\(/g,
    title: 'Spring permitAll() 可能暴露端點', description: 'permitAll() 讓端點完全公開。', suggestion: '確認該端點是有意公開的。' },
  { type: 'insecure_config', id: 'insecure_config_cross_origin_wildcard', severity: 'high', languages: ['java'], regex: /@CrossOrigin\s*\([^)]*(?:origins\s*=\s*)?['"]\*['"][^)]*\)/g,
    title: '@CrossOrigin 允許所有來源', description: 'Spring @CrossOrigin 設為萬用字元。', suggestion: '限制 origins 為信任網域。' },
  { type: 'insecure_config', id: 'insecure_config_eval', severity: 'high', languages: [], regex: /(?<![.\w])eval\s*\(/g,
    title: 'eval() 可執行任意代碼', description: 'eval() 會執行傳入的任意字串。', suggestion: '改用結構化解析或明確的分派表。' },
  // exec( 是 Python 的任意代碼 sink；JS 的 RegExp.prototype.exec 完全無害，
  // 所以這條只對 python 跑，且用 (?<![.\w]) 擋掉 .exec( 的誤報（DeepSec 註解：全規則集最大誤報來源）。
  { type: 'insecure_config', id: 'insecure_config_python_exec', severity: 'high', languages: ['python'], regex: /(?<![.\w])exec\s*\(/g,
    title: 'exec() 可執行任意 Python 代碼', description: 'exec() 會執行傳入的任意字串。', suggestion: '避免 exec()，改用明確的函式。' },
  { type: 'insecure_config', id: 'insecure_config_pickle_loads', severity: 'high', languages: ['python'], regex: /\bpickle\.loads?\s*\(/g,
    title: 'pickle 反序列化可執行任意代碼', description: 'pickle.load/loads 對不可信資料不安全。', suggestion: '改用 JSON 或安全的序列化格式。' },
  { type: 'insecure_config', id: 'insecure_config_yaml_load_without_loader', severity: 'high', languages: ['python'], regex: /\byaml\.load\s*\(\s*[^,\n)]+?\s*\)/g,
    title: 'yaml.load() 未指定安全 Loader', description: 'yaml.load() 無 SafeLoader 可執行任意物件。', suggestion: '改用 yaml.safe_load() 或明確指定 SafeLoader。' },
];

// ── AI_PATTERN_RULES（20）type='ai_pattern_error' ───────────
export const AI_PATTERN_RULES = [
  { type: 'ai_pattern_error', id: 'ai_pattern_default_password', severity: 'critical', languages: [], regex: /\b(?:password|passwd|pwd)\s*[:=]\s*['"](?:admin|password|123456|12345678|changeme)['"]/gi,
    title: '硬編碼預設密碼', description: '使用了 admin/password/123456 等預設密碼。', suggestion: '每個環境產生獨立密鑰並要求首次設定。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_admin_admin_credentials', severity: 'critical', languages: [], regex: /\b(?:username|user|login)\s*[:=]\s*['"]admin['"][\s\S]{0,120}\b(?:password|passwd|pwd)\s*[:=]\s*['"]admin['"]/gi,
    title: '出現 admin/admin 預設帳密', description: '使用者名稱與密碼都是 admin。', suggestion: '移除預設帳密，用安全流程建立初始使用者。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_hardcoded_jwt_secret', severity: 'critical', languages: [], regex: /\bJWT_SECRET\b\s*[:=]\s*['"`](?!process\.env|import\.meta\.env|os\.getenv)[^'"`]{8,}['"`]/g,
    title: 'JWT_SECRET 被硬編碼', description: 'JWT 簽章密鑰直接寫在原始碼。', suggestion: '從環境變數或 secret manager 讀取並撤銷輪換。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_sql_f_string', severity: 'high', languages: ['python'], regex: /\bf['"`][^'"`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"`]*\{[^}]+}[^'"`]*['"`]/gi,
    title: 'SQL 以 f-string 直接插值變數', description: 'SQL 查詢字串直接嵌入變數，疑似注入風險。', suggestion: '改用參數化查詢。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_dangerously_set_inner_html', severity: 'high', languages: ['javascript', 'typescript', 'jsx', 'tsx'], regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]+}\s*}/g,
    title: 'dangerouslySetInnerHTML 未見消毒', description: '渲染 HTML 前沒有明顯的 sanitizer。', suggestion: '渲染前先用 DOMPurify 等消毒。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_frontend_secret_name', severity: 'critical', languages: ['javascript', 'typescript', 'jsx', 'tsx'], regex: /\b(?:VITE|NEXT_PUBLIC|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|TOKEN|API_KEY)[A-Z0-9_]*\s*[:=]\s*['"`][^'"`]{8,}['"`]/g,
    title: '密鑰透過前端環境變數外洩', description: 'VITE_/NEXT_PUBLIC_/REACT_APP_ 前綴的變數會被打進前端 bundle。', suggestion: '密鑰移到伺服器端設定。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_jwt_none_algorithm', severity: 'critical', languages: [], regex: /\bjwt\.(?:sign|verify)\s*\([\s\S]{0,240}\balgorithms?\s*:\s*(?:\[\s*)?['"]none['"]/gi,
    title: 'JWT 接受 none 演算法', description: '允許未簽章的 JWT，任何人都能偽造 token。', suggestion: '強制要求簽章演算法（如 HS256/RS256）。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_jwt_ignore_expiration', severity: 'high', languages: [], regex: /\bjwt\.verify\s*\([\s\S]{0,240}\bignoreExpiration\s*:\s*true\b/gi,
    title: 'JWT 過期驗證被停用', description: 'ignoreExpiration: true 讓過期 token 仍然有效。', suggestion: '保持過期檢查啟用。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_tls_verification_disabled', severity: 'high', languages: [], regex: /\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=\s*['"]?0['"]?|\brejectUnauthorized\s*:\s*false\b/gi,
    title: 'TLS 憑證驗證被停用', description: '關閉憑證驗證會暴露在中间人攻擊下。', suggestion: '保持憑證驗證啟用。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_requests_verify_false', severity: 'high', languages: ['python'], regex: /\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\)\n]*\bverify\s*=\s*False\b/g,
    title: 'requests 停用 TLS 驗證', description: 'verify=False 關閉憑證檢查。', suggestion: '移除 verify=False 並設定信任的 CA。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_bcrypt_low_rounds', severity: 'high', languages: [], regex: /\bbcrypt(?:js)?\.(?:hash|genSalt)\s*\([^\)\n]*,\s*[0-4]\s*\)/gi,
    title: 'bcrypt 工作因子過低', description: 'rounds ≤ 4 讓密碼雜湊極易被暴力破解。', suggestion: '使用 ≥ 10 的 cost factor。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_math_random_token', severity: 'high', languages: [], regex: /\b(?:token|secret|apiKey|resetToken|sessionId)\b\s*[:=]\s*Math\.random\s*\(/g,
    title: '用 Math.random() 產生安全 token', description: 'Math.random() 不是密碼學安全的亂數。', suggestion: '改用 crypto.randomBytes 或 Web Crypto。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_flask_secret_key_placeholder', severity: 'critical', languages: ['python'], regex: /\b(?:app\.config\s*\[\s*['"]SECRET_KEY['"]\s*\]\s*=|SECRET_KEY\s*=)\s*['"](?:secret|dev|development|changeme|password|123456)['"]/gi,
    title: 'Flask/Django SECRET_KEY 用占位值', description: 'SECRET_KEY 是 secret/dev/changeme 之類的弱值。', suggestion: '在原始碼外產生高熵密鑰。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_fastapi_cors_credentials_wildcard', severity: 'high', languages: ['python'], regex: /\bCORSMiddleware\b[\s\S]{0,300}\ballow_origins\s*=\s*\[\s*['"]\*['"]\s*\][\s\S]{0,300}\ballow_credentials\s*=\s*True\b/g,
    title: 'CORS 萬用字元搭配 credentials', description: 'allow_origins=["*"] 又開 allow_credentials。', suggestion: '設定明確的信任 origins。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_cookie_secure_false', severity: 'high', languages: [], regex: /\b(?:res|response)\.cookie\s*\([^,\n]+,\s*[^,\n]+,\s*\{[\s\S]{0,240}\bsecure\s*:\s*false\b/gi,
    title: 'Cookie 允許走明文 HTTP', description: 'secure: false 讓 session cookie 可被竊聽。', suggestion: '正式環境設 secure: true。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_cookie_httponly_false', severity: 'high', languages: [], regex: /\b(?:res|response)\.cookie\s*\([^,\n]+,\s*[^,\n]+,\s*\{[\s\S]{0,240}\bhttpOnly\s*:\s*false\b/gi,
    title: 'Cookie 可被前端腳本讀取', description: 'httpOnly: false 讓 XSS 能偷走 cookie。', suggestion: '敏感 cookie 設 httpOnly: true。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_spring_csrf_disabled', severity: 'high', languages: ['java'], regex: /\.csrf\s*\(\s*\)\s*\.disable\s*\(\s*\)|\.csrf\s*\(\s*(?:csrf\s*->\s*)?csrf\.disable\s*\(\s*\)\s*\)/g,
    title: 'Spring CSRF 防護被停用', description: 'csrf().disable() 關閉 CSRF 檢查。', suggestion: '瀏覽器驗證的流程保持 CSRF 啟用。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_jinja_autoescape_disabled', severity: 'high', languages: ['python'], regex: /\bEnvironment\s*\([^\)\n]*\bautoescape\s*=\s*False\b/g,
    title: 'Jinja 自動跳脫被停用', description: 'autoescape=False 讓模板輸出未跳脫，易受 XSS。', suggestion: 'HTML 模板保持 autoescape 啟用。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_paramiko_auto_add_host_key', severity: 'high', languages: ['python'], regex: /\bset_missing_host_key_policy\s*\(\s*paramiko\.AutoAddPolicy\s*\(\s*\)\s*\)/g,
    title: 'SSH 自動接受未知主機金鑰', description: 'AutoAddPolicy 不驗證主機身分，易受中间人攻擊。', suggestion: '驗證並固定預期的主機金鑰。' },
  { type: 'ai_pattern_error', id: 'ai_pattern_object_storage_public_write_acl', severity: 'critical', languages: [], regex: /\b(?:ACL|acl)\s*[:=]\s*['"]public-read-write['"]|\.putObjectAcl\s*\([\s\S]{0,160}public-read-write/gi,
    title: '物件儲存開放公開寫入', description: 'ACL public-read-write 讓任何人都能覆寫物件。', suggestion: '立即移除公開寫入權限。' },
];

// 掃描順序照 DeepSec scan_patterns：config → ai pattern。
const ALL_RULES = [...CONFIG_RULES, ...AI_PATTERN_RULES];

/**
 * 掃描單一檔案的 config / AI pattern 規則。
 * @param {string} text 檔案內容
 * @param {{ target?: string|null, language?: string|null }} [opts]
 *   language：語系代碼（'python'/'java'/...），會轉小寫再比對 rule.languages；
 *   規則 languages 為空 = 全語言；缺省 language = 只跑全語言規則（照 DeepSec (language or '').lower()）。
 * @returns {Array<object>} Finding[]
 */
export function scanRules(text, { target = null, language = null } = {}) {
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) return findings;
  const lang = typeof language === 'string' ? language.toLowerCase() : '';

  for (const rule of ALL_RULES) {
    if (rule.languages.length > 0 && !rule.languages.includes(lang)) continue;

    rule.regex.lastIndex = 0; // g flag regex 是 stateful
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      const { line, column } = indexToLineCol(text, m.index);
      const end = indexToLineCol(text, m.index + m[0].length);

      findings.push(
        createFinding({
          layer: 'L1',
          severity: rule.severity,
          type: rule.type,
          rule: rule.id,
          title: rule.title,
          description: rule.description,
          evidence: m[0], // 這兩層不遮蔽（DeepSec redact=False）
          suggestion: rule.suggestion,
          line,
          column,
          endLine: end.line,
          endColumn: end.column,
          target,
        }),
      );

      if (m[0].length === 0) rule.regex.lastIndex += 1; // 防零寬死迴圈
    }
  }

  return findings;
}
