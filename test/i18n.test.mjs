import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LOCALES, LOCALE_NAMES, DEFAULT_LOCALE, FALLBACK_LOCALE,
  t, resolveLocale, detectSystemLocale, localePack, placeholdersOf,
} from '../i18n.mjs';

const ids = Object.keys(LOCALES);

test('i18n: 至少四種語系（zh-TW / en / zh-CN / ja），每種都有顯示名', () => {
  for (const id of ['zh-TW', 'en', 'zh-CN', 'ja']) assert.ok(LOCALES[id], `缺 ${id}`);
  for (const id of ids) assert.ok(LOCALE_NAMES[id], `${id} 缺顯示名`);
  assert.equal(DEFAULT_LOCALE, 'zh-TW');
  assert.equal(FALLBACK_LOCALE, 'en');
});

test('i18n: 所有語系的 key 集合與 zh-TW 完全一致，且值都是非空字串', () => {
  const base = Object.keys(LOCALES[DEFAULT_LOCALE]).sort();
  assert.ok(base.length > 80, `字典規模太小（${base.length}），UI 字串沒收乾淨`);
  for (const id of ids) {
    assert.deepEqual(Object.keys(LOCALES[id]).sort(), base, `${id} 的 key 集合與 zh-TW 不一致`);
    for (const k of base) {
      assert.equal(typeof LOCALES[id][k], 'string', `${id}.${k} 不是字串`);
      assert.ok(LOCALES[id][k].trim().length > 0, `${id}.${k} 是空字串`);
    }
  }
});

test('i18n: 每個 key 的佔位符集合跨語系一致（漏翻佔位符會顯示成 {n}）', () => {
  for (const k of Object.keys(LOCALES[DEFAULT_LOCALE])) {
    const base = placeholdersOf(LOCALES[DEFAULT_LOCALE][k]);
    for (const id of ids) {
      assert.deepEqual(placeholdersOf(LOCALES[id][k]), base, `${id}.${k} 佔位符與 zh-TW 不同`);
    }
  }
});

test('i18n: 值不得含反引號、${、<、換行（字典會內嵌進 template literal 產生的 <script>）', () => {
  for (const id of ids) {
    for (const [k, v] of Object.entries(LOCALES[id])) {
      assert.ok(!v.includes('`'), `${id}.${k} 含反引號`);
      assert.ok(!v.includes('${'), `${id}.${k} 含 \${`);
      assert.ok(!v.includes('<'), `${id}.${k} 含 <（</script> 逃逸風險）`);
      assert.ok(!v.includes('\n'), `${id}.${k} 含換行（多行訊息請在程式碼 join）`);
    }
  }
});

test('t(): 佔位符替換、同名多次替換、缺 key 回 key、缺語系退回 zh-TW', () => {
  assert.equal(t('en', 'unread', { n: 3 }), '3 unread');
  assert.equal(t('zh-TW', 'unread', { n: 3 }), '3 未讀');
  assert.equal(t('en', 'nope.key'), 'nope.key');
  assert.equal(t('xx', 'unread', { n: 1 }), t(DEFAULT_LOCALE, 'unread', { n: 1 }));
  // 佔位符值含 { } 不得被二次替換
  assert.equal(t('en', 'sendFailed', { reason: '{n}' }), 'Send failed: {n}');
});

test('resolveLocale: auto 依系統語言對應；明確指定優先；未知語言退 en', () => {
  assert.equal(resolveLocale('auto', 'zh-TW'), 'zh-TW');
  assert.equal(resolveLocale('auto', 'zh-Hant-TW'), 'zh-TW');
  assert.equal(resolveLocale('auto', 'zh-HK'), 'zh-TW');
  assert.equal(resolveLocale('auto', 'zh-Hant'), 'zh-TW');
  assert.equal(resolveLocale('auto', 'zh-CN'), 'zh-CN');
  assert.equal(resolveLocale('auto', 'zh-Hans-SG'), 'zh-CN');
  assert.equal(resolveLocale('auto', 'zh'), 'zh-CN');
  assert.equal(resolveLocale('auto', 'ja-JP'), 'ja');
  assert.equal(resolveLocale('auto', 'en-GB'), 'en');
  assert.equal(resolveLocale('auto', 'de-DE'), FALLBACK_LOCALE);
  assert.equal(resolveLocale('auto', ''), FALLBACK_LOCALE);
  assert.equal(resolveLocale(undefined, undefined), FALLBACK_LOCALE);
  assert.equal(resolveLocale('en', 'zh-TW'), 'en');
  assert.equal(resolveLocale('ja', 'zh-TW'), 'ja');
  assert.equal(resolveLocale('xx-unknown', 'zh-TW'), 'zh-TW', '不認得的偏好視同 auto');
  assert.equal(resolveLocale(' EN ', 'zh-TW'), 'en', '大小寫/空白寬容');
});

test('detectSystemLocale: LC_ALL > LC_MESSAGES > LANG（POSIX 底線轉 BCP47），都沒有才看 Intl', () => {
  assert.equal(detectSystemLocale({ env: { LANG: 'zh_TW.UTF-8' } }), 'zh-TW');
  assert.equal(detectSystemLocale({ env: { LANG: 'en_US.UTF-8', LC_ALL: 'ja_JP.UTF-8' } }), 'ja-JP');
  assert.equal(detectSystemLocale({ env: { LANG: 'C' } , intlLocale: 'zh-CN' }), 'zh-CN', 'C/POSIX 不算語言');
  assert.equal(detectSystemLocale({ env: {}, intlLocale: 'en-US' }), 'en-US');
  assert.equal(detectSystemLocale({ env: {}, intlLocale: '' }), '');
});

test('localePack: 供內嵌的精簡包（locales/names/default/fallback）', () => {
  const p = localePack();
  assert.deepEqual(Object.keys(p.locales).sort(), ids.sort());
  assert.equal(p.default, DEFAULT_LOCALE);
  assert.equal(p.fallback, FALLBACK_LOCALE);
  assert.deepEqual(p.names, LOCALE_NAMES);
  assert.doesNotThrow(() => JSON.parse(JSON.stringify(p)));
});
