// host-methods.mjs — Orca host method 名稱集中常數。
// pluginApi v1 實驗性，日後改名只動這個檔案。名稱逐字照 docs/01-api-confirmation.md §1。
export const HOST = {
  READ_CONTEXT: 'workspace.readContext',
  TERMINAL_SEND: 'terminal.sendText',
  NOTIFY: 'notifications.show',
  STORAGE_GET: 'storage.get',
  STORAGE_SET: 'storage.set',
  STORAGE_DELETE: 'storage.delete',
  STORAGE_KEYS: 'storage.keys',
  EVENTS_SUBSCRIBE: 'events.subscribe',
};
