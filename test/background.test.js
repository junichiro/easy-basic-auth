import { describe, test, before } from 'node:test';
import assert from 'node:assert/strict';
import { LOCKED_BADGE_TEXT } from '../src/extension/lib/unlocker.js';

// background.js は読み込んだ時点で chrome.* を使うため、読み込む前にフェイクを置く
function installFakeChrome() {
  const listeners = { startup: [], installed: [], message: [] };
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
      getSessionRules: async () => [],
      updateSessionRules: async () => {},
    },
  };
  return { listeners, badge };
}

const yieldToOthers = () => new Promise((resolve) => setImmediate(resolve));

describe('background.js', () => {
  let fake;
  let badgeTextAtLoad;

  before(async () => {
    fake = installFakeChrome();
    await import('../src/extension/background.js');
    await yieldToOthers();
    badgeTextAtLoad = fake.badge.text;
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

  test('ポップアップからのメッセージを受け付ける', () => {
    assert.equal(fake.listeners.message.length, 1);
  });
});
