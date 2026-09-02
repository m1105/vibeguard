// L2 SAST 規則掃描：16 條語言中立的注入類 regex（照 DeepSec rules/sast.py RULES）。
// id / type / severity / flags / 正則逐字不動；title/description/suggestion 翻中文。
// 不移植 Python AST taint 分析（JS 無 ast；語意級由 Claude LLM 補，見 l23-llm.mjs）。
// evidence 用原文（DeepSec 這層不 redact）。
// 內部去重照 sast.py _deduplicate：(type, line) 為 key，保留先出現者。

import { createFinding } from './finding.mjs';
import { indexToLineCol } from './l1-secrets.mjs';

// DeepSec 共用片段：
// _SQL_KEYWORD = (?:SELECT|INSERT|UPDATE|DELETE)
// _SQL_STRING  = 雙/單引號字串、內含 \bSQL_KEYWORD\b（允許跳脫與另一種引號）
const _SQL_STRING = String.raw`(?:"(?:[^"\\]|\\.)*\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*\b(?:SELECT|INSERT|UPDATE|DELETE)\b(?:[^'\\]|\\.)*')`;

// flags：DeepSec SastRule 預設 re.I；只有 sast_xss_inner_html 是 0（無 i）。
// 這裡統一加 g；字串 pattern 的規則用 new RegExp 以便复用 _SQL_STRING。
export const SAST_RULES = [
  { id: 'sast_sql_template_interpolation', type: 'sql_injection', severity: 'high',
    regex: /\b\w*\s*=\s*`[^`]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{[^}]+}[^`]*`/gi,
    title: 'SQL 使用模板字串插值', description: 'SQL 查詢用 template literal 直接嵌入變數。', suggestion: '改用參數化查詢或綁定變數的 query builder。' },
  { id: 'sast_sql_string_concat', type: 'sql_injection', severity: 'high',
    regex: new RegExp(String.raw`\b[A-Za-z_]\w*\s*=\s*${_SQL_STRING}\s*\+`, 'gi'),
    title: 'SQL 以字串拼接組成', description: 'SQL 查詢用字串拼接組成，疑似注入風險。', suggestion: '改用參數化查詢，不要拼接使用者輸入。' },
  { id: 'sast_sql_python_f_string_execute', type: 'sql_injection', severity: 'high',
    regex: /\bexecute\s*\(\s*f['"][^'"]*(?:SELECT|INSERT|UPDATE|DELETE)\b[^'"]*\{[^}]+}[^'"]*['"]/gi,
    title: 'execute() 收到插值的 SQL f-string', description: '資料庫 execute() 直接收到含變數的 f-string SQL。', suggestion: '用佔位符，參數另外以 tuple/物件傳入。' },
  { id: 'sast_sql_user_input_execute', type: 'sql_injection', severity: 'high',
    regex: /\b(?:(?:db|database|pool|connection|conn|client|cursor|session)\.(?:query|execute|executemany)|(?:statement|preparedStatement)\.(?:execute|executeQuery))\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|request\s*\.\s*getParameter\s*\()/gi,
    title: '資料庫執行收到使用者控制的值', description: 'query/execute 的參數直接引用 request 輸入。', suggestion: '用佔位符，request 值分開傳入。' },
  { id: 'sast_sql_concat_execute', type: 'sql_injection', severity: 'high',
    regex: new RegExp(String.raw`\b(?:execute|executemany|query|executeQuery)\s*\(\s*${_SQL_STRING}\s*\+`, 'gi'),
    title: '資料庫執行收到拼接的 SQL 字串', description: 'execute/query 收到字串拼接的 SQL。', suggestion: '用佔位符，值分開傳入。' },
  { id: 'sast_xss_inner_html', type: 'xss', severity: 'high', // DeepSec flags=0（無 i）
    regex: /\.(?:innerHTML|outerHTML)\s*=\s*(?!DOMPurify|sanitizeHtml|sanitize|['"`]\s*['"`])[^;\n]+/g,
    title: 'HTML 直接寫入 DOM', description: 'innerHTML/outerHTML 直接賦值，未見消毒。', suggestion: '用 textContent，或先消毒可信 HTML。' },
  { id: 'sast_xss_document_write', type: 'xss', severity: 'high',
    regex: /\bdocument\.write\s*\(/gi,
    title: 'document.write() 可引入 XSS', description: 'document.write() 直接寫入文件流。', suggestion: '安全地建立 DOM 節點，或先消毒。' },
  { id: 'sast_xss_dangerously_set_inner_html', type: 'xss', severity: 'high',
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*(?!DOMPurify|sanitizeHtml|sanitize)[^}]*\breq\.(?:query|body|params)\b[^}]*}\s*}/gi,
    title: 'dangerouslySetInnerHTML 收到使用者控制的 HTML', description: '渲染的 HTML 直接來自 request 輸入。', suggestion: '用文字渲染，或消毒不可信 HTML。' },
  { id: 'sast_ssrf_fetch_user_url', type: 'ssrf', severity: 'medium',
    regex: /\b(?:fetch|axios\.(?:get|post|put|patch|delete)|got(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|httpx\.(?:get|post|put|patch|delete)|urllib\.request\.urlopen)\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:args|form|json))/gi,
    title: 'HTTP 請求使用使用者控制的 URL', description: 'fetch/requests 等的 URL 直接來自 request 輸入（SSRF 風險）。', suggestion: '對外連主機做白名單並驗證 URL scheme。' },
  { id: 'sast_path_traversal_fs_user_input', type: 'path_traversal', severity: 'high',
    regex: /\b(?:fs(?:\.promises)?\.(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rm)|open|Path\(|send_file)\s*\([^\)\n]*(?:req\.(?:query|body|params)|request\.(?:args|form|json)|params?\[)/gi,
    title: '檔案路徑包含使用者控制的輸入', description: '檔案操作的路徑直接引用 request 輸入。', suggestion: '以固定 base 解析路徑，拒絕跳出 base 的穿越。' },
  { id: 'sast_insecure_deserialization_pickle', type: 'insecure_deserialization', severity: 'high',
    regex: /\bpickle\.loads?\s*\([^\)\n]*(?:request|req\.|input|body|data)/gi,
    title: 'pickle 反序列化可能使用者控制的資料', description: 'pickle 對不可信資料可執行任意代碼。', suggestion: '不可信資料改用 JSON 等安全格式。' },
  { id: 'sast_insecure_deserialization_yaml', type: 'insecure_deserialization', severity: 'high',
    regex: /\byaml\.load\s*\([^\)\n]*(?:request|req\.|input|body|data)(?![^)]*SafeLoader)/gi,
    title: 'yaml.load() 未用 SafeLoader 反序列化不可信資料', description: 'yaml.load() 無 SafeLoader 可執行任意物件。', suggestion: '不可信 YAML 用 yaml.safe_load()。' },
  { id: 'sast_command_injection_os_system', type: 'command_injection', severity: 'high',
    regex: /\b(?:os\.system|subprocess\.(?:call|run|Popen|check_call|check_output)|child_process\.exec(?:Sync)?)\s*\([^\)\n]*(?:request|req\.|input|body|params|\$\{)/gi,
    title: '命令執行包含使用者控制的輸入', description: 'os.system/subprocess/child_process 的參數引用外部輸入。', suggestion: '用參數陣列與嚴格白名單，避免 shell=True。' },
  { id: 'sast_command_injection_shell_true', type: 'command_injection', severity: 'high',
    regex: /\bsubprocess\.(?:call|run|Popen|check_call|check_output)\s*\([^\)]*\bshell\s*=\s*True\b/gi,
    title: '命令經 shell 執行動態字串', description: 'shell=True 讓命令字元被 shell 解析。', suggestion: '傳參數陣列並移除 shell=True。' },
  { id: 'sast_open_redirect_user_input', type: 'open_redirect', severity: 'medium',
    regex: /\b(?:res|response)\.redirect\s*\(\s*(?:req\.(?:query|body|params)|request\.(?:query|body|params))|\bredirect\s*\(\s*(?:request\.(?:args|GET|POST)|req\.(?:query|body|params))/gi,
    title: '重導向目標來自使用者輸入', description: 'redirect 的目標 URL 直接來自 request（open redirect 風險）。', suggestion: '只重導向到相對路徑或白名單主機。' },
  { id: 'sast_information_leakage_error_details', type: 'information_leakage', severity: 'medium',
    regex: /\b(?:res|response)\.(?:send|json)\s*\([^;\n]*(?:err(?:or)?|exception|stack)\b/gi,
    title: '原始錯誤詳情回給客戶端', description: '回應直接包含 error/exception/stack。', suggestion: '詳細錯誤記在內部 log，對外回通用訊息。' },
];

/**
 * 掃描單一檔案的 L2 SAST 規則（regex 部分；AST taint 由 LLM 層補）。
 * @param {string} text 檔案內容
 * @param {{ target?: string|null }} [opts]
 * @returns {Array<object>} Finding[]（layer 一律 'L2'，(type,line) 去重留先）
 */
export function scanSast(text, { target = null } = {}) {
  const findings = [];
  if (typeof text !== 'string' || text.length === 0) return findings;

  for (const rule of SAST_RULES) {
    rule.regex.lastIndex = 0; // g flag regex 是 stateful
    let m;
    while ((m = rule.regex.exec(text)) !== null) {
      // 誤報修正（與 DeepSec 原版刻意不同，docs/02 記差異）：innerHTML/outerHTML
      // 規則的空字串豁免前瞻會被 \s* 回溯打穿（`= ''` 帶空格時失效）——
      // regex 是 quirk 測試鎖住的，改在命中後檢查右值：純空字串（清空容器）無注入風險，丟棄
      if (rule.id === 'sast_xss_inner_html') {
        const rhs = m[0].slice(m[0].indexOf('=') + 1).trim().replace(/;$/, '');
        if (rhs === "''" || rhs === '""' || rhs === '``') {
          if (m[0].length === 0) rule.regex.lastIndex += 1;
          continue;
        }
      }
      const { line, column } = indexToLineCol(text, m.index);
      const end = indexToLineCol(text, m.index + m[0].length);

      findings.push(
        createFinding({
          layer: 'L2',
          severity: rule.severity,
          type: rule.type,
          rule: rule.id,
          title: rule.title,
          description: rule.description,
          evidence: m[0], // 這層不遮蔽
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

  // 照 sast.py _deduplicate：(type, line) 為 key，保留先出現者，維持首次出現順序
  const seen = new Set();
  return findings.filter((f) => {
    const key = f.type + ' ' + f.line;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
