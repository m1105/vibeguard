// watcher.mjs — worktree 檔案監聽 + debounce + LLM 並發閘門（ISSUE-09）。
// Orca 沒有檔案事件（docs/01 §2），worker 自己跑 fs.watch（macOS/Windows 支援 recursive）。

import { watch as fsWatch } from 'node:fs';
import { join } from 'node:path';
import { shouldSkipPath } from './scanner.mjs';

export class WorktreeWatcher {
  /**
   * @param {{ onFileReady: (e:{worktreeId:string, path:string}) => void,
   *   onIgnoreChanged?: (e:{worktreeId:string, path:string}) => void,
   *   debounceMs?: number,
   *   deps?: { watch?: Function, now?: Function, log?: Function } }} opts
   */
  constructor({ onFileReady, onIgnoreChanged, debounceMs = 2000, deps = {} }) {
    this.onFileReady = onFileReady;
    // .vibeguard-ignore 變動要專門通知（它副檔名不支援、會被 shouldSkipPath 擋，
    // 但使用者按「忽略/免檢」後 agent 寫它，worker 必須重新套用規則）
    this.onIgnoreChanged = onIgnoreChanged ?? (() => {});
    this.debounceMs = debounceMs;
    this.watch = deps.watch ?? fsWatch;
    this.now = deps.now ?? Date.now;
    this.log = deps.log ?? (() => {});
    this.watchers = new Map(); // worktreeId → { handle, rootPath }
    this.timers = new Map();   // 絕對路徑 → timeout
  }

  worktreeIds() {
    return [...this.watchers.keys()];
  }

  addWorktree(worktreeId, rootPath) {
    if (this.watchers.has(worktreeId)) return;
    let handle;
    try {
      handle = this.watch(rootPath, { recursive: true }, (_event, filename) => {
        if (!filename) return;
        // 忽略檔變動優先放行（不掃它，但要通知 worker 重新套用忽略規則）
        if (String(filename).split(/[\\/]/).pop() === '.vibeguard-ignore') {
          this._debounced(worktreeId, join(rootPath, filename), this.onIgnoreChanged);
          return;
        }
        // 跳過清單用相對路徑判斷（node_modules、測試檔、生成檔等）
        if (shouldSkipPath(filename)) return;
        const fullPath = join(rootPath, filename);
        this._debounced(worktreeId, fullPath, this.onFileReady);
      });
    } catch (err) {
      this.log(`watch 失敗（${rootPath}）：${err?.message ?? err}`);
      return;
    }
    // 目錄被刪等錯誤：log 並移除該 worktree，不讓整個 worker 崩
    handle.on?.('error', (err) => {
      this.log(`watcher 錯誤（${worktreeId}）：${err?.message ?? err}`);
      this.removeWorktree(worktreeId);
    });
    this.watchers.set(worktreeId, { handle, rootPath });
  }

  _debounced(worktreeId, fullPath, cb) {
    const existing = this.timers.get(fullPath);
    if (existing) clearTimeout(existing);
    this.timers.set(fullPath, setTimeout(() => {
      this.timers.delete(fullPath);
      (cb ?? this.onFileReady)({ worktreeId, path: fullPath });
    }, this.debounceMs));
  }

  removeWorktree(worktreeId) {
    const entry = this.watchers.get(worktreeId);
    if (!entry) return;
    this.watchers.delete(worktreeId);
    try { entry.handle.close?.(); } catch { /* 已關閉 */ }
    // 清掉該 worktree 底下的 pending timer
    for (const [path, timer] of this.timers) {
      if (path.startsWith(entry.rootPath)) {
        clearTimeout(timer);
        this.timers.delete(path);
      }
    }
  }

  dispose() {
    for (const id of [...this.watchers.keys()]) this.removeWorktree(id);
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
  }
}

// LLM 並發閘門：同時最多 max 個 fn 在跑，其餘 FIFO 排隊。
export function createGate(max = 2) {
  let running = 0;
  const queue = [];
  const pump = () => {
    while (running < max && queue.length > 0) {
      running += 1;
      const { fn, resolve, reject } = queue.shift();
      Promise.resolve()
        .then(fn)
        .then(resolve, reject)
        .finally(() => { running -= 1; pump(); });
    }
  };
  return (fn) => new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    pump();
  });
}
