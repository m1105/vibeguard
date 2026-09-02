# VibeGuard — DeepSec 來源忠實度分析（/tmp/DeepSec @ fff031f）

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

## 語言 gating 規則
規則有 `languages` 欄位時，只對該語言跑（`(language||'').toLowerCase() in languages`）。python-only 規則的 JS 對應注意：Python lookbehind `(?<![.\w])` 在 Node ≥16 可直接用。
