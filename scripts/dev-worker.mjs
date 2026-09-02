// scripts/dev-worker.mjs — 本地模擬 Orca host 跑 worker（除錯用，不进插件包功能）。
// 用法：node scripts/dev-worker.mjs  （Ctrl+C 結束）
// host.call 用本地 stub：storage 存到 /tmp/vibeguard-dev-storage.json，其餘記 log。
import { readFile, writeFile } from 'node:fs/promises';
import activate, { deactivate } from '../main.mjs';

const STORAGE_PATH = '/tmp/vibeguard-dev-storage.json';
let store = {};
try { store = JSON.parse(await readFile(STORAGE_PATH, 'utf8')); } catch { /* 首次 */ }

const orca = {
  commands: { register: (id) => console.log('[command registered]', id) },
  events: { on: (name) => console.log('[event subscribed]', name) },
  host: {
    call: async (method, params) => {
      console.log('[host.call]', method, JSON.stringify(params ?? {}).slice(0, 120));
      if (method === 'storage.get') return { value: store[params.key] };
      if (method === 'storage.set') {
        store[params.key] = params.value;
        await writeFile(STORAGE_PATH, JSON.stringify(store, null, 1));
        return { ok: true };
      }
      if (method === 'storage.keys') return { keys: Object.keys(store) };
      if (method === 'workspace.readContext') return null;
      if (method === 'notifications.show') return { delivered: true };
      if (method === 'events.subscribe') return { subscribed: params.events };
      return null;
    },
  },
  log: (m) => console.log('[worker log]', m),
};

process.on('uncaughtException', (e) => { console.error('[FATAL uncaught]', e); process.exit(1); });
process.on('unhandledRejection', (e) => { console.error('[FATAL unhandledRejection]', e); process.exit(1); });

await activate(orca);
console.log('[dev-worker] activated, watching… (Ctrl+C to stop)');
