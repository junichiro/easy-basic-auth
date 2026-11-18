import { describe, test, before } from 'node:test';
import assert from 'node:assert/strict';
import { LOCKED_BADGE_TEXT } from '../src/extension/lib/unlocker.js';

// background.js は読み込んだ時点で chrome.* を使うため、読み込む前にフェイクを置く
function installFakeChrome({ initialRules = [] } = {}) {
  const listeners = { startup: [], installed: [], message: [] };
  let sessionRules = [...initialRules];
  const badge = { text: undefined };
  const sessionStorage = {};
  globalThis.chrome = {
    runtime: {
      id: 'test-extension-id',
      getManifest: () => ({ version: '1.0.1' }),
      getURL: (file) => `chrome-extension://test-extension-id/${file}`,
      onStartup: { addListener: (listener) => listeners.startup.push(listener) },
      onInstalled: { addListener: (listener) => listeners.installed.push(listener) },
      onMessage: { addListener: (listener) => listeners.message.push(listener) },
    },
    storage: {
      session: {
        get: async (keys) => Object.fromEntries([keys].flat().filter((key) => key in sessionStorage)
          .map((key) => [key, sessionStorage[key]])),
        set: async (items) => { Object.assign(sessionStorage, items); },
      },
    },
    action: {
      setBadgeText: async ({ text }) => { badge.text = text; },
      setBadgeBackgroundColor: async () => {},
    },
    declarativeNetRequest: {
      getSessionRules: async () => sessionRules,
      updateSessionRules: async ({ removeRuleIds = [], addRules = [] }) => {
        sessionRules = [...sessionRules.filter((rule) => !removeRuleIds.includes(rule.id)), ...addRules];
      },
    },
  };
  return { listeners, badge, sessionRules: () => sessionRules };
}

const yieldToOthers = () => new Promise((resolve) => setImmediate(resolve));

describe('background.js', () => {
  let fake;
  let badgeTextAtLoad;
  let rulesAtLoad;

  before(async () => {
    // 無効化→有効化の後のように、解除の状態は消えたがセッションルールだけが残っている状態から始める
    fake = installFakeChrome({ initialRules: [{ id: 1, priority: 1, action: { type: 'modifyHeaders' }, condition: {} }] });
    await import('../src/extension/background.js');
    await yieldToOthers();
    badgeTextAtLoad = fake.badge.text;
    rulesAtLoad = fake.sessionRules().length;
  });

  test('読み込まれた時点でバッジを状態に合わせる (インストール・再読み込み・有効化)', () => {
    assert.equal(badgeTextAtLoad, LOCKED_BADGE_TEXT);
  });

  test('ブラウザの起動 (onStartup) でロックのバッジを付ける', async () => {
    // ブラウザの起動時は onStartup のリスナーがないと service worker が起動しないため、登録されていることを確かめる
    assert.equal(fake.listeners.startup.length, 1);
    fake.badge.text = undefined;
    await fake.listeners.startup[0]();
    assert.equal(fake.badge.text, LOCKED_BADGE_TEXT);
  });

  test('読み込まれた時点で、解除されていなければ残っているセッションルールを消す', () => {
    assert.equal(rulesAtLoad, 0);
  });

  test('インストール・更新・再読み込み (onInstalled) でも service worker を起こしてロックの状態に合わせる', async () => {
    assert.equal(fake.listeners.installed.length, 1);
    fake.badge.text = undefined;
    await fake.listeners.installed[0]();
    assert.equal(fake.badge.text, LOCKED_BADGE_TEXT);
  });

  test('ポップアップからのメッセージを受け付ける', () => {
    assert.equal(fake.listeners.message.length, 1);
  });
});
