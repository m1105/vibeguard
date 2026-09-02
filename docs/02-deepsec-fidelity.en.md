# VibeGuard — DeepSec source fidelity analysis (DeepSec @ fff031f)

_English translation of [`02-deepsec-fidelity.md`](02-deepsec-fidelity.md); the Chinese file is the normative one when they differ._

Scope: `deepsec/shield/` — `scanner.py`, `rules/patterns.py`, `rules/sast.py`, `rules/ai_audit.py`, `dedup.py`, `ignore.py`.
**Every rule id, regex, severity and threshold in the JS port must match this document verbatim. Nothing is invented.**

## Key corrections (relative to the original plan)

1. **Rule ids carry a prefix**: secret rules are `hardcoded_secret_aws_access_key` etc., not `aws_access_key`.
2. **Sensitive assignments are CRITICAL** (not high): rule id `hardcoded_secret_assignment`; with high entropy the id becomes `hardcoded_secret_high_entropy_assignment` (severity still critical). Evidence format: `"<variable> = <redacted value>"`.
3. **Entropy thresholds**: contextual (assignment context) length 16–180, entropy ≥ 3.8; non-contextual length ≥ 24, entropy ≥ 4.5 (we only use contextual). Conditions: no whitespace, contains both letters and digits.
4. **Placeholder set (exact)**: the value lower-cased with spaces replaced by `-` must be in {changeme, change-me, example, sample, placeholder, your-key, your-api-key, your-secret, your-token, test, test-key, dummy, fake, todo}.
5. **Environment-variable reference is judged on the whole line**: `/(?:process\.env|os\.getenv|os\.environ|import\.meta\.env|ENV\[)/`.
6. **Position math**: line = `text.count('\n', 0, offset) + 1`; column = `offset - text.rfind('\n', 0, offset)` (1-based).
7. **Evidence masking `_redact`**: ≤ 8 chars → `***`; otherwise `first4...last4`.
8. **`seen_ranges`**: ranges hit by secret rules are registered; a sensitive assignment overlapping an already-hit range is skipped (no double report of the same value). CONFIG / AI-pattern rules do not use `seen_ranges`.
9. **Two dedup layers**:
   - inside SAST: key `(type, line)`, **first wins** (AST results are inserted first, so they take priority);
   - global `unique_findings`: key `(rule, target, line, evidence)`, first wins;
   - our JS adds a cross-layer rule: same `(type, target, line)` in different layers → keep the higher layer (L3 > L2 > L1).
10. **L2 SAST = 16 language-neutral regexes + Python AST.** The Python AST part is **not ported** (no `ast` in JS; the LLM covers it); all 16 regexes are ported, layer `L2`.
11. **L3 local semantic checks (`ai_audit.audit_semantics`) are pure regex and ported directly**: endpoint detection (Flask and Express regex sets) + 4 rules (missing_authentication high / missing_rate_limiting medium / missing_input_validation medium / missing_error_handling low), confidence fixed at 0.65, layer `L3`. DeepSec ships L3 disabled by default (`ScanOptions.l3=False`); we follow.
12. **LLM result normalization (`audit_with_llm`)**: severity outside the list → medium; line coercion: bool → null, int → max(1, v), integral float → int, string → max(1, int(float(v))), failure → null; confidence: numbers clamped to 0–1 (> 1 is *not* divided by 100 — only strings are), string table {critical: 0.95, very high: 0.9, high: 0.85, medium: 0.6, moderate: 0.6, low: 0.35, very low: 0.2, info: 0.2, informational: 0.2, unknown: 0.6}, `'80%'` → 0.8, failure → 0.6; rule fixed `l3_llm_semantic_review`, layer `L3`, type `missing_security_measure`, description defaults to the title.
13. **Scanner skip lists (verbatim)**:
    - SUPPORTED_SUFFIXES: `.py→python, .js/.mjs/.cjs→javascript, .ts→typescript, .tsx→tsx, .jsx→jsx, .java→java, .go→go, .rb→ruby, .php→php, .cs→csharp, .rs→rust, .yaml/.yml→yaml, .json→json`
    - IGNORED_DIRECTORIES: `.git .deepsec node_modules bower_components dist out build coverage .venv venv .venv64 __pycache__ vendor third_party site-packages .next .nuxt .svelte-kit Pods .tox .mypy_cache .pytest_cache .gradle`, plus anything starting with `.venv` / `venv-` / `venv3`
    - TEST_DIRECTORIES: `test tests __tests__ spec specs fixtures fixture testdata test_data examples example demo demos mocks __mocks__ testvectors wycheproof benchmarks`
    - GENERATED_SUFFIXES: `.min.js .min.css .bundle.js .bundle.css -lock.json .lock.json .map .pb.go _pb2.py .g.dart .generated.ts`
    - TEST_FILE_MARKERS: `.test. .spec. _test. _spec.`
    - REPORT_FILENAMES: `deepsec-report.json deepsec-report.sarif deepsec.sarif deepsec-findings.json`
    - VibeGuard additions (not in DeepSec, marked in `shield/scanner.mjs`): agent-state directories `.omc .omx .claude .serena .codegraph`, test-artifact directories `test-results playwright-report playwright-artifacts`, localization directories `i18n l10n locales locale translations`, and `.vibeguard-learned.json` as a report file.
14. **Ignore semantics**: DeepSec marks matched findings `dismissed=true` with a reason; **we simplify to filtering them out** (difference recorded here).
15. **Not ported**: Python AST taint analysis, agent_security (prompt_injection / tool_abuse / data_exfil), supply_chain (typosquatting / dependency_confusion). The hallucinated-package seed list for supply_chain is kept as an empty placeholder in `seeds/known-packages.json`.

## Language gating

When a rule has a `languages` field it only runs for those languages (`(language || '').toLowerCase() in languages`). For Python-only rules note that Python's lookbehind `(?<![.\w])` works unchanged in Node ≥ 16.
