// scanner.mjs — 分層調度 + 路徑過濾 + 效能閘門（對應 DeepSec scanner.py）。
// 只做「單檔掃描編排」；檔案監聽在 watcher.mjs（ISSUE-09）。
// 跳過清單逐字照 docs/02-deepsec-fidelity.md #13（= DeepSec scanner.py）。

import { uniqueFindings } from './finding.mjs';
import { scanSecrets } from './l1-secrets.mjs';
import { scanEntropy } from './l1-entropy.mjs';
import { scanRules } from './l1-rules.mjs';
import { scanSast } from './l2-sast.mjs';
import { auditSemantics } from './l3-local.mjs';

// ── 清單（逐字照 fidelity #13）──────────────────────────────
export const SUPPORTED_SUFFIXES = {
  '.py': 'python', '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
  '.ts': 'typescript', '.tsx': 'tsx', '.jsx': 'jsx', '.java': 'java', '.go': 'go',
  '.rb': 'ruby', '.php': 'php', '.cs': 'csharp', '.rs': 'rust',
  '.yaml': 'yaml', '.yml': 'yaml', '.json': 'json',
};

export const IGNORED_DIRECTORIES = new Set([
  // vibeguard 擴充（非 DeepSec 原文）：.omc/.claude 是 agent 狀態目錄，掃它們沒意義
  '.git', '.deepsec', 'node_modules', 'bower_components', 'dist', 'out', 'build',
  'coverage', '.venv', 'venv', '.venv64', '__pycache__', 'vendor', 'third_party',
  'site-packages', '.next', '.nuxt', '.svelte-kit', 'Pods', '.tox', '.mypy_cache',
  '.pytest_cache', '.gradle', '.omc', '.omx', '.claude', '.serena', '.codegraph',
]);

export const TEST_DIRECTORIES = new Set([
  'test', 'tests', '__tests__', 'spec', 'specs', 'fixtures', 'fixture', 'testdata',
  'test_data', 'examples', 'example', 'demo', 'demos', 'mocks', '__mocks__',
  'testvectors', 'wycheproof', 'benchmarks',
  // vibeguard 擴充（非 DeepSec 原文）：Playwright 等測試產物目錄
  'test-results', 'playwright-report', 'playwright-artifacts',
]);

// vibeguard 擴充（非 DeepSec 原文）：翻譯/文案目錄——字串是 UI 文案不是密鑰，誤報率高
export const LOCALIZATION_DIRECTORIES = new Set([
  'i18n', 'l10n', 'locales', 'locale', 'translations',
]);

export const GENERATED_SUFFIXES = [
  '.min.js', '.min.css', '.bundle.js', '.bundle.css', '-lock.json', '.lock.json',
  '.map', '.pb.go', '_pb2.py', '.g.dart', '.generated.ts',
];

export const TEST_FILE_MARKERS = ['.test.', '.spec.', '_test.', '_spec.'];

export const REPORT_FILENAMES = new Set([
  'deepsec-report.json', 'deepsec-report.sarif', 'deepsec.sarif', 'deepsec-findings.json', '.vibeguard-learned.json',
]);

export const MAX_FILE_BYTES = 500 * 1024; // >500KB 跳過

// ── 路徑工具 ────────────────────────────────────────────────

// 副檔名小寫查表；不支援 → null
export function detectLanguage(path) {
  if (typeof path !== 'string') return null;
  const base = path.split(/[\\/]/).pop();
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return null;
  return SUPPORTED_SUFFIXES[base.slice(dot).toLowerCase()] ?? null;
}

// 是否跳過此路徑（includeTests=true 時不擋測試檔/目錄）
export function shouldSkipPath(path, { includeTests = false } = {}) {
  if (typeof path !== 'string' || path.length === 0) return true;
  const parts = path.split(/[\\/]/);
  const filename = parts[parts.length - 1];
  const lower = filename.toLowerCase();
  const directories = parts.slice(0, -1);

  // 不支援的副檔名
  if (!detectLanguage(path)) return true;

  // 報告檔 / 生成檔
  if (REPORT_FILENAMES.has(lower)) return true;
  if (GENERATED_SUFFIXES.some((s) => lower.endsWith(s))) return true;

  // 一律跳過的目錄（含 .venv* / venv-* / venv3* 前綴）
  if (directories.some((d) => IGNORED_DIRECTORIES.has(d)
    || d.startsWith('.venv') || d.startsWith('venv-') || d.startsWith('venv3'))) return true;

  // 測試檔/目錄（預設跳過）
  if (!includeTests) {
    if (directories.some((d) => TEST_DIRECTORIES.has(d.toLowerCase()))) return true;
    if (TEST_FILE_MARKERS.some((mk) => lower.includes(mk))) return true;
  }

  // 翻譯/文案檔（一律跳過）：i18n 字串常被誤判成硬編碼密鑰（名字像 token、值是文案）
  if (directories.some((d) => LOCALIZATION_DIRECTORIES.has(d.toLowerCase()))) return true;

  return false;
}

// ── 單檔掃描編排（照 DeepSec scan_text）────────────────────

/**
 * @param {string} text 檔案內容
 * @param {string} target 檔案路徑
 * @param {object} [options] { l1=true, l2=true, l3=false, llm=false, dedup=true, includeTests=false, ignoreRuleIds:Set }
 * @param {object} [deps] { llmScan: async ({path,text,language}) => Finding[] }（測試注入用）
 * @returns {Promise<{ findings: Array, elapsedMs: number, filesScanned: 0|1, layers: string[], skipped?: string }>}
 */
export async function scanText(text, target, options = {}, deps = {}) {
  let llmError = null;
  const t0 = performance.now();
  const { l1 = true, l2 = true, l3 = false, llm = false, dedup = true, ignoreRuleIds, learned } = options;

  if (typeof text !== 'string' || text.length > MAX_FILE_BYTES) {
    return { findings: [], elapsedMs: round2(performance.now() - t0), filesScanned: 0, layers: [], skipped: 'too_large' };
  }

  const language = detectLanguage(target);
  const layers = [];
  let findings = [];

  if (l1) {
    const seenRanges = []; // secrets 先跑、entropy 共用（照 DeepSec scan_patterns）
    findings.push(...scanSecrets(text, { target, seenRanges }));
    findings.push(...scanEntropy(text, { target, seenRanges }));
    findings.push(...scanRules(text, { target, language }));
    layers.push('L1');
  }
  if (l2) {
    findings.push(...scanSast(text, { target }));
    layers.push('L2');
  }
  if (l3) {
    findings.push(...auditSemantics(text, { target, language }));
    layers.push('L3');
  }
  if (llm) {
    try {
      if (typeof deps.llmScan !== 'function') throw new Error('llmScan not provided');
      findings.push(...await deps.llmScan({ path: target, text, language, learned }));
      layers.push('LLM');
    } catch (err) {
      layers.push('LLM_FAILED'); // 不報錯，繼續回傳本地結果
      llmError = String(err?.message ?? err).slice(0, 300); // 真因帶回（掃描記錄可見）
    }
  }

  if (ignoreRuleIds instanceof Set && ignoreRuleIds.size > 0) {
    // 刻意簡化：命中即移除（DeepSec 是標 dismissed，差異見 fidelity #14）
    findings = findings.filter((f) => !ignoreRuleIds.has(f.rule));
  }
  if (dedup) {
    findings = uniqueFindings(findings);
  }

  return { findings, elapsedMs: round2(performance.now() - t0), filesScanned: 1, layers, llmError };
}

function round2(n) {
  return Math.round(n * 100) / 100;
}
