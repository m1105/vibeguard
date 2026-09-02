// learning.mjs — 誤報學習（vibeguard 擴充，非 DeepSec 原文）。
// 使用者透過「🙈 忽略這筆 / 🚫 此檔免檢」寫進 .vibeguard-ignore 的 finding，
// 由 main.mjs 在重掃時捕捉到並記進 <repo根>/.vibeguard-learned.json。
// 之後 LLM 掃描同檔時：(1) 學到的標題注入 prompt 請它別再報；(2) 結果後過濾同標題 finding。
// 比對維度：rule + repo 相對路徑 + 標題正規化後相等（不同檔案的同名問題互不影响）。

export const LEARNED_FILENAME = '.vibeguard-learned.json';
const MAX_ENTRIES = 100; // 每 repo 上限，最舊的先丟
const TITLE_MAX = 200;

export function normalizeTitle(s) {
  return String(s ?? '').trim().toLowerCase().replace(/\s+/g, ' ');
}

// 防禦式解析：壞 JSON / 非陣列 / 缺欄位的條目一律丟掉
export function parseLearned(text) {
  let v;
  try { v = JSON.parse(text); } catch { return []; }
  if (!Array.isArray(v)) return [];
  return v.filter((e) => e && typeof e === 'object' && !Array.isArray(e)
    && typeof e.rule === 'string' && typeof e.target === 'string' && typeof e.title === 'string');
}

export function serializeLearned(entries) {
  return JSON.stringify(entries, null, 2) + '\n';
}

export function isLearned(finding, entries, rel) {
  if (!finding || !rel) return false;
  const t = normalizeTitle(finding.title);
  return entries.some((e) => e.rule === finding.rule && e.target === rel && normalizeTitle(e.title) === t);
}

// 回傳新陣列；已存在（或無 rel）時回傳原陣列（reference 不變，呼叫端據此判斷要不要寫檔）
export function addLearned(entries, finding, rel, at) {
  if (!rel || isLearned(finding, entries, rel)) return entries;
  const next = [...entries, {
    rule: String(finding.rule ?? ''),
    target: rel,
    title: String(finding.title ?? '').slice(0, TITLE_MAX),
    at,
  }];
  return next.length > MAX_ENTRIES ? next.slice(next.length - MAX_ENTRIES) : next;
}
