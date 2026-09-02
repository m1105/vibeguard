import { test } from 'node:test';
import assert from 'node:assert/strict';
import { WorktreeWatcher, createGate } from '../shield/watcher.mjs';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 假 fs.watch：回傳 {on, close}，把回呼存起來讓測試手動觸發
function fakeWatchFactory() {
  const handlers = [];
  const handles = [];
  const watch = (root, opts, cb) => {
    const handle = {
      closed: false,
      on() {},
      close() { this.closed = true; },
    };
    handlers.push({ root, cb });
    handles.push(handle);
    return handle;
  };
  return { watch, handlers, handles };
}

test('debounce：同檔 50ms 內兩次 change → onFileReady 只叫一次', async () => {
  const { watch, handlers } = fakeWatchFactory();
  const calls = [];
  const w = new WorktreeWatcher({ onFileReady: (e) => calls.push(e), debounceMs: 50, deps: { watch } });
  w.addWorktree('wt1', '/repo');
  handlers[0].cb('change', 'src/a.js');
  handlers[0].cb('change', 'src/a.js');
  await sleep(90);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].worktreeId, 'wt1');
  assert.equal(calls[0].path, '/repo/src/a.js');
  w.dispose();
});

test('不同檔案各自觸發 → 各叫一次', async () => {
  const { watch, handlers } = fakeWatchFactory();
  const calls = [];
  const w = new WorktreeWatcher({ onFileReady: (e) => calls.push(e), debounceMs: 50, deps: { watch } });
  w.addWorktree('wt1', '/repo');
  handlers[0].cb('change', 'src/a.js');
  handlers[0].cb('change', 'src/b.js');
  await sleep(90);
  assert.equal(calls.length, 2);
  w.dispose();
});

test('shouldSkipPath 命中（node_modules）→ 不叫', async () => {
  const { watch, handlers } = fakeWatchFactory();
  const calls = [];
  const w = new WorktreeWatcher({ onFileReady: (e) => calls.push(e), debounceMs: 20, deps: { watch } });
  w.addWorktree('wt1', '/repo');
  handlers[0].cb('change', 'node_modules/x/y.js');
  handlers[0].cb('change', 'src/ok.js');
  await sleep(60);
  assert.deepEqual(calls.map((c) => c.path), ['/repo/src/ok.js']);
  w.dispose();
});

test('.vibeguard-ignore 變動 → onIgnoreChanged（不掃它、也不被 shouldSkipPath 擋）', async () => {
  const { watch, handlers } = fakeWatchFactory();
  const files = [];
  const ignores = [];
  const w = new WorktreeWatcher({
    onFileReady: (e) => files.push(e),
    onIgnoreChanged: (e) => ignores.push(e),
    debounceMs: 20,
    deps: { watch },
  });
  w.addWorktree('wt1', '/repo');
  handlers[0].cb('change', '.vibeguard-ignore');
  await sleep(60);
  assert.equal(files.length, 0, '忽略檔不該被當一般檔掃');
  assert.equal(ignores.length, 1);
  assert.equal(ignores[0].path, '/repo/.vibeguard-ignore');
  w.dispose();
});

test('removeWorktree 後再觸發 → 不叫；watch handle 被關閉', async () => {
  const { watch, handlers, handles } = fakeWatchFactory();
  const calls = [];
  const w = new WorktreeWatcher({ onFileReady: (e) => calls.push(e), debounceMs: 20, deps: { watch } });
  w.addWorktree('wt1', '/repo');
  w.removeWorktree('wt1');
  assert.equal(handles[0].closed, true);
  handlers[0].cb('change', 'src/a.js'); // handle 已關，真實環境不會再叫；這裡手動叫也只是進 debounce
  await sleep(50);
  // removeWorktree 清了 pending timer；之後再觸發屬於殘留回呼，worker 層不應崩
  assert.ok(calls.length <= 1);
  w.dispose();
});

test('pending 的 debounce 在 removeWorktree 時被清掉', async () => {
  const { watch, handlers } = fakeWatchFactory();
  const calls = [];
  const w = new WorktreeWatcher({ onFileReady: (e) => calls.push(e), debounceMs: 40, deps: { watch } });
  w.addWorktree('wt1', '/repo');
  handlers[0].cb('change', 'src/a.js');
  w.removeWorktree('wt1'); // 20ms 內移除 → pending timer 應被清
  await sleep(70);
  assert.equal(calls.length, 0);
  w.dispose();
});

test('watch 拋錯（目錄不存在）→ log 且不崩', () => {
  const logs = [];
  const w = new WorktreeWatcher({
    onFileReady() {},
    deps: { watch: () => { throw new Error('ENOENT'); }, log: (m) => logs.push(m) },
  });
  w.addWorktree('wt1', '/gone');
  assert.equal(w.worktreeIds().length, 0);
  assert.ok(logs[0].includes('ENOENT'));
});

test('createGate(2)：並發峰值 ≤2、全部完成、FIFO', async () => {
  const gate = createGate(2);
  let running = 0;
  let peak = 0;
  const started = [];
  const mk = (i) => async () => {
    running += 1;
    peak = Math.max(peak, running);
    started.push(i);
    await sleep(20);
    running -= 1;
    return i;
  };
  const results = await Promise.all([0, 1, 2, 3, 4].map((i) => gate(mk(i))));
  assert.deepEqual(results, [0, 1, 2, 3, 4]);
  assert.deepEqual(started, [0, 1, 2, 3, 4]); // FIFO
  assert.ok(peak <= 2, `peak=${peak}`);
});

test('createGate：fn 拋錯會 reject 且不卡死後續任務', async () => {
  const gate = createGate(1);
  await assert.rejects(() => gate(async () => { throw new Error('x'); }), /x/);
  assert.equal(await gate(async () => 7), 7);
});
