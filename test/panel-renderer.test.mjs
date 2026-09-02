import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPanelHtml, safeInlineJson } from '../panel-renderer.mjs';
import { t as tr, LOCALES, LOCALE_NAMES, DEFAULT_LOCALE, FALLBACK_LOCALE } from '../i18n.mjs';

test('safeInlineJson: < 轉義防 </script> 逃逸', () => {
  const s = safeInlineJson({ x: '</script><script>alert(1)</script>' });
  assert.ok(!s.includes('</script>'));
  assert.ok(s.includes('\\u003c'));
  // 仍是合法 JSON
  assert.deepEqual(JSON.parse(s), { x: '</script><script>alert(1)</script>' });
});

test('buildPanelHtml: 內嵌資料可被解析回來', () => {
  const groups = { wt1: { unknown: [{ rule: 'r1', severity: 'high', target: '/a.js', line: 3 }] } };
  const html = buildPanelHtml({ generatedAt: '2026-08-29T07:00:00Z', groups });
  const m = html.match(/window\.__VIBEGUARD_DATA__ \|\| (.*?);\n/);
  assert.ok(m, '找不到內嵌資料');
  const data = JSON.parse(m[1]); // \u003c 跳脫 JSON.parse 原生支援
  assert.equal(data.groups.wt1.unknown[0].rule, 'r1');
  assert.equal(data.generatedAt, '2026-08-29T07:00:00Z');
});

test('buildPanelHtml: 不含 fetch/外部資源（CSP connect-src none 相容）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  assert.ok(!html.includes('fetch('));
  assert.ok(!html.includes('src="http'));
  assert.ok(!html.includes('href="http'));
});

test('buildPanelHtml: 含 bridge 三要素與 textContent 渲染', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  assert.ok(html.includes('orca-panel-action'));
  assert.ok(html.includes('terminal.sendText'));
  assert.ok(html.includes('workspace.readContext'));
  assert.ok(html.includes('textContent'));
  assert.ok(!html.includes('innerHTML ='));
});

test('開檔指令：路徑單引號跳脫（防檔名 shell 注入，enter:true 會直接執行）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  const m = html.match(/function sq\(s\) \{[^}]+\}/);
  assert.ok(m, '模板裡找不到 sq 跳脫函式');
  const sq = eval(`(${m[0]})`); // 從模板抽出純字串函式單測
  // 雙引號、分號、$() 全部關進單引號裡 → shell 不展開
  assert.equal(sq('a"; rm -rf ~; #'), `'a"; rm -rf ~; #'`);
  assert.equal(sq('x$(whoami)y'), `'x$(whoami)y'`);
  // 單引號本身 → '\'' 標準跳脫
  assert.equal(sq("a'b"), `'a'\\''b'`);
  // buildOpenCommand 必須走 sq，不再裸插雙引號
  assert.ok(html.includes("'orca file open ' + sq("));
  assert.ok(!html.includes("'orca file open \"'"));
});

test('修復訊息消毒：clean 清控制字元/換行並截斷（防 prompt injection 進終端）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  const m = html.match(/function clean\(s, max\) \{[^}]+\}/);
  assert.ok(m, '模板裡找不到 clean 消毒函式');
  const clean = eval(`(${m[0]})`);
  assert.equal(clean('a\nb\rc\x1bd\x07e'), 'a b c d e');
  assert.equal(clean(null), '');
  assert.equal(clean('x'.repeat(600)).length, 500);
  // 四個訊息 builder 都要過 clean，不許裸接 finding 欄位（sq(...) 是 shell 跳脫、
  // textContent 顯示路徑不進終端，皆不在此列）
  for (const raw of ["+ (f.title || '')", "+ (f.description || '')", "+ (f.suggestion || '')"]) {
    assert.ok(!html.includes(raw), `發現未消毒插值：${raw}`);
  }
});

test('buildPanelHtml: 渲染邏輯含 foundAt 時間顯示', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('f.foundAt'));
  assert.ok(html.includes('toLocaleTimeString'));
});

test('buildPanelHtml: 含已修正區塊邏輯', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [] });
  assert.ok(html.includes('renderResolved'));
  assert.ok(html.includes('已修正'));
});

test('buildPanelHtml: 修復訊息優先用內嵌 terminalId（不按 focus）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {} });
  assert.ok(html.includes('DATA.terminals'));
  assert.ok(html.includes('f.worktreeId'));
});

test('buildPanelHtml: agent 身分不確定時不自動 Enter（agentSure 閘門）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  assert.ok(html.includes('agentSure'), 'sendToTerminal 要看 agentSure 決定 enter');
});

test('開檔按鈕路由：優先 agent 終端 + ! 前綴（TUI 本機 shell 模式）；沒 agent 才落 shell', () => {
  // agent 閒置時沒有 spinner 特徵會被誤判成 shell → 純指令打進對話。
  // ! 前綴誤中真 shell 只會 event not found（無害），所以 agent(!) 永遠優先。
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  const openIdx = html.indexOf('📄 開檔');
  assert.ok(openIdx !== -1);
  const agentBranch = html.indexOf("'!' + cmd", openIdx);
  const shellBranch = html.indexOf("sendToTerminal(cmd, f.worktreeId, 'shell')", openIdx);
  assert.ok(agentBranch !== -1, '要有 agent 的 ! 分支');
  assert.ok(shellBranch !== -1, '要保留 shell 備援分支');
  assert.ok(agentBranch < shellBranch, '開檔要先試 agent(!)，shell 只是備援');
});

test('sendShellCommand：背景 shell 指令也優先 agent(!)（誤判 shell 會把指令打進 agent 對話）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {} });
  const fnIdx = html.indexOf('async function sendShellCommand');
  assert.ok(fnIdx !== -1);
  const fnEnd = html.indexOf('function reportShellResult', fnIdx);
  const body = html.slice(fnIdx, fnEnd);
  assert.ok(body.includes("'!' + cmd"), 'sendShellCommand 要先試 agentSure 的 agent 終端');
  assert.ok(body.indexOf("'!' + cmd") < body.lastIndexOf('.shell'), 'agent(!) 在 shell 之前');
});

test('buildPanelHtml: 含開 Issue 待修按鈕與訊息', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {} });
  assert.ok(html.includes('buildIssueMessage'));
  assert.ok(html.includes('開 Issue'));
  assert.ok(html.includes('gh issue create'));
});

test('buildPanelHtml: 忽略按鈕走 shell 指令直接寫 .vibeguard-ignore（不經過 AI、不污染開發對話）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {} });
  assert.ok(html.includes('buildIgnoreCommand'));
  assert.ok(html.includes('忽略'));
  assert.ok(html.includes('.vibeguard-ignore'));
  assert.ok(html.includes('>> '), '用 append 方式寫檔');
  assert.ok(!html.includes('請在 repo 根目錄的 .vibeguard-ignore'), '不再送 AI 提示詞');
});

test('buildPanelHtml: 每列顯示 description（使用者要知道命中了哪個變數/原因）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes("className = 'desc'"), 'findingRow 要渲染 desc 元素');
  assert.ok(html.includes('f.description'));
});

test('buildPanelHtml: 背景更新保留檢視狀態（localStorage：捲動/已讀/折疊）', () => {
  // 面板每次掃描都會重烤——狀態必須存 localStorage，不然使用者正在看的東西被刷掉
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('localStorage'));
  assert.ok(html.includes('vg.scroll'), '捲動位置要保存/還原');
  assert.ok(html.includes('vg.read'), '已讀集合要持久化');
  assert.ok(html.includes('vg.open'), '折疊狀態要持久化');
});

test('buildPanelHtml: 未讀標記 + 全部已讀按鈕', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('badge-new'), '未讀列要有 NEW 徽章');
  assert.ok(html.includes('全部已讀'));
  assert.ok(html.includes('keyOf'), '需要 finding key 函式（rule+target+line）');
});

test('buildPanelHtml: 通知開關（Orca 風格 switch）+ 寫 state 檔指令', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], settings: { notify: true, stateFile: '/p/.notify-state' } });
  assert.ok(html.includes('啟用通知'));
  assert.ok(html.includes('notify-toggle'), '要有 switch checkbox');
  assert.ok(html.includes('DATA.settings'), '初始狀態從 worker 內嵌讀');
  assert.ok(html.includes('printf'), 'toggle 用 shell 指令寫 state 檔');
});

test('buildPanelHtml: LLM 框架/模型選擇器（寫 .llm-state）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], settings: { llm: { framework: 'claude', model: 'haiku', stateFile: '/p/.llm-state' } } });
  assert.ok(html.includes('llm-framework'), '框架下拉選單');
  assert.ok(html.includes('<select id="llm-model"'), '模型也要是下拉選單（不是文字輸入）');
  assert.ok(html.includes('sonnet') && html.includes('opus'), 'claude 模型預設清單');
  assert.ok(html.includes('.llm-state'));
});

test('buildPanelHtml: 重啟按鈕常駐 + 掃描狀態列', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('id="restart-worker"'), '重啟按鈕要常駐（不只 worker 死了才出現）');
  assert.ok(html.includes('最後掃描'), 'summary 要顯示最後掃描時間（回答「有沒有在掃」）');
});

test('buildPanelHtml: worker 心跳警示 + 重新啟用按鈕（只指引 toggle，不做 exit 式重啟）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('worker 疑似停止'));
  assert.ok(html.includes('重新啟用'));
  assert.ok(html.includes("t('restartHow')"), '重啟只能指引使用者 toggle（worker 自行 exit 會吃 host 的 maxRestarts 額度）');
  assert.ok(!html.includes('process.exit'), '面板不得觸發 exit 式重啟');
  assert.ok(html.includes('generatedAt'), '心跳看 DATA.generatedAt');
});

test('buildPanelHtml: 嚴重/注意分區 + 折疊 + 過濾 chips + 開檔按鈕', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {} });
  assert.ok(html.includes('sec-serious'));
  assert.ok(html.includes('僅嚴重'));
  assert.ok(html.includes('僅注意'));
  assert.ok(html.includes("createElement('details')"));
  assert.ok(html.includes('📄 開檔'));
  assert.ok(html.includes('buildOpenCommand'));
});

test('buildPanelHtml: issue 徽章邏輯與 vibeguard-key 標記', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {}, issues: {} });
  assert.ok(html.includes('vibeguard-key:'));
  assert.ok(html.includes('DATA.issues'));
  assert.ok(html.includes('已開（待修）'));
  assert.ok(html.includes('已完成'));
});

test('buildPanelHtml: 含忽略這筆按鈕（shell 指令版）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], resolved: [], terminals: {}, issues: {} });
  assert.ok(html.includes('buildDismissCommand'));
  assert.ok(html.includes('忽略這筆'));
  assert.ok(html.includes('ignoreKey'));
});

test('buildPanelHtml: 禁用頁內 location.reload（會把 srcdoc frame 打進壞狀態→pong 停→watchdog 40 秒判死；更新一律靠 dev watcher 重掛）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(!html.includes('location.reload('), 'reload 呼叫是面板 40 秒暫停的元兇（註解提及無妨）');
  assert.ok(html.includes('data-age'), '資料齡時鐘保留（純顯示）');
});

test('buildPanelHtml: 代碼片段渲染（mono、命中行標記）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('f.snippet'), 'findingRow 要渲染 snippet');
  assert.ok(html.includes("'snippet'"), '要有 snippet 樣式 class');
});

test('buildPanelHtml: 即時 dashboard 入口（🚀 按鈕，orca goto 開 panel-server 頁）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], settings: { dashboardUrl: 'http://127.0.0.1:47391/?token=x' } });
  assert.ok(html.includes('id="open-dashboard"'));
  assert.ok(html.includes('orca goto --url'));
  assert.ok(html.includes('dashboardUrl'));
});

test('buildPanelHtml: 烤出的 script 語法合法（template literal 反斜線教訓的正式驗收）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  const i = html.indexOf('<' + 'script>') + 8;
  const j = html.indexOf('</' + 'script>');
  assert.doesNotThrow(() => new Function(html.slice(i, j)));
});

test('buildPanelHtml: 回應 Orca panel watchdog（ping→pong，不回會被判無響應暫停）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('orca-panel-ping'), '要監聽 shell 的 ping');
  assert.ok(html.includes('orca-panel-pong'), '要回 pong（帶 pingId）');
  assert.ok(html.includes('pingId'));
});

test('忽略/免檢按鈕走 curl → /api/action（worker 端寫檔；printf 進終端太脆已棄用）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], settings: { dashboardUrl: 'http://127.0.0.1:47391/?token=x' } });
  assert.ok(html.includes('/api/action'), '要打 doAction 端點');
  assert.ok(html.includes("'dismiss'") && html.includes("'ignore'"), '兩種忽略動作');
  assert.ok(html.includes('curl -s'), '借 agent 終端執行 curl');
});

test('掃描記錄渲染 llmError（LLM 失敗原因要在面板上看得到）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('llmError'), 'renderScans 要顯示 LLM 失敗原因');
});

test('掃描記錄圖示依實際嚴重度：medium 只亮 🟠，別讓人去「嚴重」區白找', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  const m = html.match(/function scanBadge\(s\) \{[\s\S]*?\n\}/);
  assert.ok(m, '模板裡找不到 scanBadge');
  // scanBadge 走 t() 查字典：抽出來單測時綁一個 zh-TW 的 t
  const scanBadge = new Function('t', `return (${m[0]});`)((k, p) => tr('zh-TW', k, p));
  // 使用者實例：routes.ts 6 筆全 medium → 亮紅燈會誤導成「嚴重」
  assert.deepEqual(scanBadge({ count: 6, sev: { medium: 6 } }), { icon: '🟠', text: '注意 6' });
  assert.deepEqual(scanBadge({ count: 1, sev: { critical: 1 } }), { icon: '🔴', text: '嚴重 1' });
  assert.deepEqual(scanBadge({ count: 2, sev: { high: 2 } }), { icon: '🔴', text: '嚴重 2' });
  assert.deepEqual(scanBadge({ count: 7, sev: { critical: 1, medium: 6 } }), { icon: '🔴', text: '嚴重 1 · 注意 6' });
  assert.deepEqual(scanBadge({ count: 3, sev: { low: 3 } }), { icon: '🟡', text: '低 3' });
  assert.deepEqual(scanBadge({ count: 0, sev: {} }), { icon: '✅', text: '' });
  // 舊記錄沒有 sev 欄位（worker 換版前寫的）→ 沿用舊行為，不炸
  assert.deepEqual(scanBadge({ count: 6 }), { icon: '🔴', text: '' });
  assert.deepEqual(scanBadge({ count: 0 }), { icon: '✅', text: '' });
});

test('「注意」區預設展開：收合等於看不到（使用者實測抱怨「掃到卻沒顯示」）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes("renderSection(nWrap, t('normal'), 'normal', normal, true)"), '注意區 defaultOpen 要是 true');
});

// ── i18n（多國語系：字典內嵌、自動偵測、就地切換）──
function extractPack(html) {
  const start = html.indexOf('const I18N = ');
  assert.ok(start !== -1, '找不到 I18N 字典內嵌');
  const end = html.indexOf(';\n', start);
  return JSON.parse(html.slice(start + 'const I18N = '.length, end));
}

test('buildPanelHtml: i18n 字典整包內嵌 + t() + 語言切換器 + 自動偵測', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('function t('), '要有 t(key, params) 查字典函式');
  assert.ok(html.includes('vg.lang'), '語言偏好要存 localStorage（vg.lang）');
  assert.ok(html.includes('id="lang-select"'), '要有語言切換器');
  assert.ok(html.includes('navigator.language'), 'auto 模式要看瀏覽器語言');
  assert.ok(html.includes('documentElement.lang'), '要同步 <html lang>');
  const pack = extractPack(html);
  assert.deepEqual(Object.keys(pack.locales).sort(), Object.keys(LOCALES).sort(), '內嵌的語系集合要與 i18n.mjs 一致');
  assert.deepEqual(pack.locales['zh-TW'], LOCALES['zh-TW'], '內嵌字典必須就是 i18n.mjs 的字典（單一真相）');
  assert.deepEqual(pack.names, LOCALE_NAMES);
  assert.equal(pack.default, DEFAULT_LOCALE);
  assert.equal(pack.fallback, FALLBACK_LOCALE);
});

test('buildPanelHtml: en 字典的英文值確實在 HTML 裡（抽查）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  for (const s of ['Mark all read', 'No issues found', 'Recent scan log', 'Security overview', 'Suggested fix']) {
    assert.ok(html.includes(s), `缺英文：${s}`);
  }
  for (const s of ['セキュリティ概要', '安全总览']) assert.ok(html.includes(s), `缺：${s}`);
});

test('buildPanelHtml: 靜態 UI 字串走 data-i18n / data-i18n-title 標記 + applyI18n 套用', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  for (const key of ['notifyToggle', 'chipAll', 'chipSerious', 'chipNormal', 'markAllRead', 'scanAll', 'openDashboard', 'restart', 'settings', 'llmScanToggle', 'llmPicker', 'langLabel', 'emptyTitle', 'emptySub', 'subtitle']) {
    assert.ok(html.includes(`data-i18n="${key}"`), `靜態字串 ${key} 要標 data-i18n`);
    assert.ok(LOCALES['zh-TW'][key], `字典要有 ${key}`);
  }
  for (const key of ['scanAllTitle', 'openDashboardTitle', 'restartTitle', 'notifyToggleTitle', 'llmScanToggleTitle', 'llmPickerTitle', 'statusTitle', 'langTitle']) {
    assert.ok(html.includes(`data-i18n-title="${key}"`), `tooltip ${key} 要標 data-i18n-title`);
    assert.ok(LOCALES['zh-TW'][key], `字典要有 ${key}`);
  }
  assert.ok(html.includes("querySelectorAll('[data-i18n]')"), '初始化要跑一次套用');
  assert.ok(html.includes("querySelectorAll('[data-i18n-title]')"), 'title 屬性也要套用');
  assert.ok(html.includes('function applyI18n'), '要有 applyI18n');
});

test('buildPanelHtml: 語言切換就地重渲染 + 同步 worker（.locale 走 /api/action），不用 location.reload', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [], settings: { locale: 'auto', dashboardUrl: 'http://127.0.0.1:47391/?token=x' } });
  assert.ok(!html.includes('location.reload('), '既有禁令不變：reload 會把 frame 打壞（watchdog 40 秒判死）');
  assert.ok(html.includes("kind: 'locale'"), '切語言要通知 worker 寫 .locale');
  assert.ok(html.includes('DATA.settings.locale') || html.includes('settings.locale'), 'worker 端偏好要當作 localStorage 之後的次順位');
  assert.ok(html.includes('renderAll('), '切語言後要重渲染全部區塊');
});

test('buildPanelHtml: 動態字串不再硬編碼中文（抽查關鍵訊息都走 t()）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  const script = html.slice(html.indexOf('<' + 'script>'), html.indexOf('</' + 'script>'));
  // 字典本身也內嵌在 script 區，所以不能用「script 區無中文」判斷；
  // 改抓呼叫形式：每個關鍵訊息都要以 t('key' 出現，才代表真的走字典而不是硬編碼
  for (const key of ['statusGenerated', 'statusNoData', 'unread', 'watchMeta', 'noScanYet', 'wrongFocus', 'noTerminal', 'sendFailed',
    'openRequested', 'fixRequested', 'issueRequested', 'ignoredFile', 'dismissed', 'noRepoRoot', 'notifyUpdated', 'llmScanOn', 'llmScanOff',
    'scanAllStarted', 'llmSwitched', 'restartHow', 'dashboardOpened', 'workerDead', 'agoSeconds', 'agoMinutes', 'issueClosed', 'issueOpen',
    'btnOpen', 'btnFix', 'btnIssue', 'btnIgnoreFile', 'btnDismiss', 'resolvedTitle', 'scanLogTitle', 'scanFailed', 'scanResult',
    'fixHeader', 'fixFooter', 'issueHeader', 'issueBody', 'issueFooter', 'msgFile', 'msgProblem', 'msgWhy', 'msgSuggest']) {
    assert.ok(script.includes(`t('${key}'`), `訊息 ${key} 要走 t()`);
    assert.ok(LOCALES['zh-TW'][key], `字典要有 ${key}`);
  }
});

test('buildPanelHtml: 掃描記錄的 note 優先用 noteKey 翻譯（舊記錄只有 note 文字時沿用）', () => {
  const html = buildPanelHtml({ generatedAt: null, groups: {}, scans: [] });
  assert.ok(html.includes('noteKey'), '要看 noteKey');
  assert.ok(html.includes('noteParams'), '要帶 noteParams');
});
