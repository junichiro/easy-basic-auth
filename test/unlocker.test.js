import { describe, test, before } from 'node:test';
import assert from 'node:assert/strict';
import { createUnlocker, createMessageHandler, LOCKED_BADGE_TEXT } from '../src/extension/lib/unlocker.js';
import { buildExtensionVault } from '../src/generate.js';
import { createKdfParams, deriveKey } from '../src/extension/lib/vault-crypto.js';

const MASTER = 'master password 1234';
const EXTENSION_ID = 'test-extension-id';
let vault;

before(async () => {
  const kdf = createKdfParams({ iterations: 1000 });
  const key = await deriveKey(MASTER, kdf);
  vault = await buildExtensionVault([
    { domain: 'a.example.com', includeSubdomains: false, username: 'u', password: 'p', enabled: true },
    { domain: 'b.example.com', includeSubdomains: true, username: 'u', password: 'p', enabled: true },
  ], key, kdf);
});

// 処理の途中で他の処理が割り込めるよう、マクロタスク 1 回分待つ
const yieldToOthers = () => new Promise((resolve) => setImmediate(resolve));

// chrome.* API の最小限のフェイク
function createFakeChrome({ loadVault = async () => vault, manifestVersion = '1.0.1' } = {}) {
  let sessionRules = [];
  const storage = {};
  const badge = { text: null };
  return {
    sessionRules: () => sessionRules,
    badge,
    deps: {
      dnr: {
        getSessionRules: async () => {
          await yieldToOthers();
          return sessionRules;
        },
        updateSessionRules: async ({ removeRuleIds = [], addRules = [] }) => {
          await yieldToOthers();
          const remaining = sessionRules.filter((rule) => !removeRuleIds.includes(rule.id));
          const ids = new Set(remaining.map((rule) => rule.id));
          if (addRules.some((rule) => ids.has(rule.id))) throw new Error('duplicate rule id');
          sessionRules = [...remaining, ...addRules];
        },
      },
      storage: {
        get: async (key) => ({ [key]: storage[key] }),
        set: async (items) => { Object.assign(storage, items); },
      },
      action: {
        setBadgeText: async ({ text }) => { badge.text = text; },
        setBadgeBackgroundColor: async () => {},
      },
      loadVault,
      manifestVersion,
    },
  };
}

describe('createUnlocker', () => {
  test('初期状態はロック中で、バッジにロック表示を出す', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
    await unlocker.refreshBadge();
    assert.equal(fake.badge.text, LOCKED_BADGE_TEXT);
  });

  test('正しいマスターパスワードでセッションルールを登録する', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    assert.deepEqual(await unlocker.unlock(MASTER), { ok: true, ruleCount: 2 });
    assert.equal(fake.sessionRules().length, 2);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: true });
    assert.equal(fake.badge.text, '');
  });

  test('誤ったマスターパスワードではルールを登録しない', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    const result = await unlocker.unlock('wrong password!!');
    assert.equal(result.ok, false);
    assert.match(result.error, /マスターパスワード/);
    assert.equal(fake.sessionRules().length, 0);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
  });

  test('再度アンロックしても既存ルールを置き換えて重複させない', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    await unlocker.unlock(MASTER);
    await unlocker.unlock(MASTER);
    assert.equal(fake.sessionRules().length, 2);
  });

  test('ロックするとセッションルールを削除する', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    await unlocker.unlock(MASTER);
    await unlocker.lock();
    assert.equal(fake.sessionRules().length, 0);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
    assert.equal(fake.badge.text, LOCKED_BADGE_TEXT);
  });
});

describe('createUnlocker の version 確認', () => {
  test('vault の version が manifest と違えば、再読み込みを促して解除しない', async () => {
    const fake = createFakeChrome({
      loadVault: async () => ({ ...vault, extensionVersion: '1.0.2' }),
      manifestVersion: '1.0.1',
    });
    const unlocker = createUnlocker(fake.deps);
    const result = await unlocker.unlock(MASTER);
    assert.equal(result.ok, false);
    assert.match(result.error, /再読み込み/);
    assert.equal(fake.sessionRules().length, 0);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
  });

  test('解除済みのまま version が食い違ったら、解除を断るとともにロックする', async () => {
    let extensionVersion = '1.0.1';
    const fake = createFakeChrome({
      loadVault: async () => ({ ...vault, extensionVersion }),
      manifestVersion: '1.0.1',
    });
    const unlocker = createUnlocker(fake.deps);
    assert.equal((await unlocker.unlock(MASTER)).ok, true);
    // 設定 UI で保存したが拡張機能を再読み込みしていない状態
    extensionVersion = '1.0.2';
    const result = await unlocker.unlock(MASTER);
    assert.equal(result.ok, false);
    assert.match(result.error, /再読み込み/);
    assert.equal(fake.sessionRules().length, 0);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
    assert.equal(fake.badge.text, LOCKED_BADGE_TEXT);
  });

  test('vault の version が manifest と一致すれば解除する', async () => {
    const fake = createFakeChrome({
      loadVault: async () => ({ ...vault, extensionVersion: '1.0.1' }),
      manifestVersion: '1.0.1',
    });
    assert.deepEqual(await createUnlocker(fake.deps).unlock(MASTER), { ok: true, ruleCount: 2 });
  });

  test('version を記録していない古い vault でも解除できる', async () => {
    const fake = createFakeChrome();
    assert.equal((await createUnlocker(fake.deps).unlock(MASTER)).ok, true);
  });
});

describe('createUnlocker の同時実行', () => {
  test('解除が同時に 2 回来ても、ルール ID が重複せずに両方成功する', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    const results = await Promise.all([unlocker.unlock(MASTER), unlocker.unlock(MASTER)]);
    assert.deepEqual(results.map((result) => result.ok), [true, true]);
    assert.equal(fake.sessionRules().length, 2);
  });

  test('解除の直後にロックが来たら、受け付けた順に処理してロック状態で終わる', async () => {
    const fake = createFakeChrome();
    const unlocker = createUnlocker(fake.deps);
    await Promise.all([unlocker.unlock(MASTER), unlocker.lock()]);
    assert.equal(fake.sessionRules().length, 0);
    assert.deepEqual(await unlocker.getStatus(), { unlocked: false });
  });
});

describe('createMessageHandler', () => {
  const sender = { id: EXTENSION_ID };

  test('status / unlock / lock メッセージを処理する', async () => {
    const fake = createFakeChrome();
    const handle = createMessageHandler(createUnlocker(fake.deps), EXTENSION_ID);
    assert.deepEqual(await handle({ type: 'status' }, sender), { unlocked: false });
    assert.equal((await handle({ type: 'unlock', password: MASTER }, sender)).ok, true);
    assert.deepEqual(await handle({ type: 'lock' }, sender), { ok: true });
    assert.equal(fake.sessionRules().length, 0);
  });

  test('他の拡張機能からのメッセージは拒否する', async () => {
    const fake = createFakeChrome();
    const handle = createMessageHandler(createUnlocker(fake.deps), EXTENSION_ID);
    const result = await handle({ type: 'unlock', password: MASTER }, { id: 'other' });
    assert.equal(result.ok, false);
    assert.equal(fake.sessionRules().length, 0);
  });

  test('未知のメッセージにはエラーを返す', async () => {
    const fake = createFakeChrome();
    const handle = createMessageHandler(createUnlocker(fake.deps), EXTENSION_ID);
    assert.equal((await handle({ type: 'unknown' }, sender)).ok, false);
  });
});
