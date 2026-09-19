# VibeGuard — DeepSec 來源忠實度分析（/tmp/DeepSec @ fff031f）

_English: [`02-deepsec-fidelity.en.md`](02-deepsec-fidelity.en.md)_

分析對象：`deepsec/shield/` 的 scanner.py、rules/patterns.py、rules/sast.py、rules/ai_audit.py、dedup.py、ignore.py。
**所有 JS port 的規則 id、正則、嚴重度、閾值必須與此文件一致（逐字），不得自創。**

## 關鍵校正（相對原規劃書）

1. **rule id 有前綴**：密鑰規則是 `hardcoded_secret_aws_access_key` 等，不是 `aws_access_key`。
2. **敏感賦值 severity 是 CRITICAL**（不是 high）：rule id `hardcoded_secret_assignment`；高熵時 id 改為 `hardcoded_secret_high_entropy_assignment`（severity 仍 critical）。evidence 格式：`"<變數名> = <redacted值>"`。
3. **熵閾值**：contextual（賦值上下文）長度 16–180、熵 ≥3.8；非 contextual 長度 ≥24、熵 ≥4.5（我們只用 contextual）。條件：無空白、含字母且含數字。
4. **placeholder 集合（精確）**：值 lowercase + 空格換 `-` 後 ∈ {changeme, change-me, example, sample, placeholder, your-key, your-api-key, your-secret, your-token, test, test-key, dummy, fake, todo}。
5. **環境變數引用判斷是對「整行」**：`/(?:process\.env|os\.getenv|os\.environ|import\.meta\.env|ENV\[)/`。
6. **位置換算**：line = `text.count('\n',0,offset)+1`；column = `offset - text.rfind('\n',0,offset)`（1-based）。
7. **evidence 遮蔽 `_redact`**：≤8 字元 → `***`；否則 `前4...後4`。
8. **seen_ranges 機制**：密鑰規則命中範圍會登記，敏感賦值若與已命中範圍重疊則跳過（避免同值報兩次）。config/AI pattern 不用 seen_ranges。
9. **dedup 有兩層**：
   - SAST 內部：`(type, line)` 為 key，**先出現者保留**（AST 結果先放所以優先）。
   - 全域 `unique_findings`：`(rule, target, line, evidence)` 為 key，保留第一筆。
   - 我們的 JS 版額外加跨層規則：同 `(type, target, line)` 不同 layer → 保留 layer 高者（L3>L2>L1）。
10. **L2 SAST = 16 條語言中立 regex + Python AST**。Python AST 部分**不移植**（JS 沒有 ast；由 Claude LLM 補上），16 條 regex 完整移植，layer 標 `L2`。
11. **L3 本地語意檢查（ai_audit.audit_semantics）也是純 regex，可直接移植**：端點偵測（Flask/Express 兩套 regex）+ 4 條規則（missing_authentication high / missing_rate_limiting medium / missing_input_validation medium / missing_error_handling low），confidence 固定 0.65，layer `L3`。DeepSec 預設 L3 關閉（ScanOptions.l3=False），我們跟隨。
12. **LLM 結果正規化**（audit_with_llm）：severity 不在列→medium；line coercion：bool→null、int→max(1,v)、float 整數→int、字串→max(1,int(float(v))) 失敗→null；confidence：數字 clamp 0–1（>1 不除 100！只有字串才除）；字串對照表 {critical:0.95, very high:0.9, high:0.85, medium:0.6, moderate:0.6, low:0.35, very low:0.2, info:0.2, informational:0.2, unknown:0.6}，'80%'→0.8，失敗→0.6；rule 固定 `l3_llm_semantic_review`，layer `L3`，type `missing_security_measure`，description 缺省用 title。
13. **scanner 跳過清單（逐字）**：
    - SUPPORTED_SUFFIXES: `.py→python, .js/.mjs/.cjs→javascript, .ts→typescript, .tsx→tsx, .jsx→jsx, .java→java, .go→go, .rb→ruby, .php→php, .cs→csharp, .rs→rust, .yaml/.yml→yaml, .json→json`
    - IGNORED_DIRECTORIES: `.git .deepsec node_modules bower_components dist out build coverage .venv venv .venv64 __pycache__ vendor third_party site-packages .next .nuxt .svelte-kit Pods .tox .mypy_cache .pytest_cache .gradle`，外加 startswith `.venv`/`venv-`/`venv3`
    - TEST_DIRECTORIES: `test tests __tests__ spec specs fixtures fixture testdata test_data examples example demo demos mocks __mocks__ testvectors wycheproof benchmarks`
    - GENERATED_SUFFIXES: `.min.js .min.css .bundle.js .bundle.css -lock.json .lock.json .map .pb.go _pb2.py .g.dart .generated.ts`
    - TEST_FILE_MARKERS: `.test. .spec. _test. _spec.`
    - REPORT_FILENAMES: `deepsec-report.json deepsec-report.sarif deepsec.sarif deepsec-findings.json`
14. **ignore 語義**：命中的 finding 標 `dismissed=true` + reason，**不是刪除**（我們簡化為過濾移除，差異記錄於此）。
15. **不移植**：Python AST taint 分析、agent_security（prompt_injection/tool_abuse/data_exfil）、supply_chain（typosquatting/dependency_confusion）。其中 supply_chain 的幻覺包種子清單保留在 `seeds/known-packages.json`（後續 issue）。

16. **【VibeGuard 偏離】非高熵賦值的形狀分流（2026-09-18，dogfooding 實測）**：DeepSec 對 `_sensitive_assignments` 命中的任何非 placeholder 值一律報 `hardcoded_secret_assignment` critical。實測誤報成災（`OPEN_TOKEN = "pay_corp:open"`、`COUNTRY_TOKEN = '中華民國|R\.?O\.?C\.?'` regex、`…_CREDENTIAL_ID = "harness-dev-runtime"`、註解裡的 `PASSWORD='strong-pass'` 範例）。`l1-entropy.mjs` 的 `triageLowEntropyAssignment` 對**非高熵**值分三級：值含空白／regex-glob 中繼字元／非 ASCII → **skip**（pattern 或文案）；變數名尾巴是名字類後綴（`_ID`、`_PREFIX`、`_NAME`、`…Hash` 等，刻意不含 `key`）→ **skip**；命中行是註解、或值無數字 → **low**（confidence 0.3，標題註明「低風險」）；其餘（含數字、非註解、熵 < 3.8）→ critical 照舊。**高熵路徑（`hardcoded_secret_high_entropy_assignment`）完全不受影響**。舊測試「含空白值也報 critical」已改為新行為。

17. **【VibeGuard 偏離】`sast_xss_inner_html` 的右值分析（2026-09-19，dogfooding 實測）**：DeepSec 的 regex 只認 `DOMPurify`／`sanitize` 開頭，且只看到換行為止，所以自訂跳脫函式（`esc()`）、純字面值三元（`open ? '&#9652;' : '&#9662;'`）、多行敘述全部報 high；實測單一檔案 9 筆命中全是誤報。regex 逐字保留（quirk 測試仍鎖著），改在命中後由 `shield/l2-xss-triage.mjs` 取整個敘述（跨行到分號）分析右值：每個插入值都是字面值 → **不報**；每個動態部分都包在已知跳脫／消毒／數值函式裡 → **不報**；右值是同檔定義的函式呼叫、`.map(fn).join()` 或區域變數 → **到同一個檔找定義**，分析每個 `return` 與每次賦值（遞迴 ≤3 層），全部安全才算已跳脫；由產生函式組成但找不到定義、或只有部分能確認 → **medium**（confidence 0.4，標題加「待確認」，說明要確認什麼）；完全沒看到跳脫或解析不了 → **high 照舊**（寧可報不可漏）。這不是 JS parser：陣列 `push()`／`join()` 組字串等樣式無法確認，會落在 medium。原 quirk「`innerHTML = DOMPurify.sanitize(x)` 等號後有空格仍命中」在 regex 層仍在，但 `scanSast` 不再回報。

## 語言 gating 規則
規則有 `languages` 欄位時，只對該語言跑（`(language||'').toLowerCase() in languages`）。python-only 規則的 JS 對應注意：Python lookbehind `(?<![.\w])` 在 Node ≥16 可直接用。
