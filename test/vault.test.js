import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { getConfigStatus, sealConfig, openConfig, readConfigEntries, UnsupportedConfigError, BrokenConfigError } from '../src/vault.js';
import { createKdfParams, deriveKey, DecryptionError, bytesToBase64, IV_BYTES } from '../src/extension/lib/vault-crypto.js';
import { StateError } from '../src/errors.js';

const PASSWORD = 'master password 1234';
const entries = [{ id: '1', domain: 'a.example.com', username: 'u', password: 'secret-p' }];

async function makeSealed() {
  const kdf = createKdfParams({ iterations: 1000 });
  const key = await deriveKey(PASSWORD, kdf);
  return { key, config: await sealConfig({ counter: 5, kdf, key, entries }) };
}

describe('getConfigStatus', () => {
  test('config が無ければ未初期化', () => {
    assert.deepEqual(getConfigStatus(null), { initialized: false, needsMigration: false });
  });

  test('エントリのある v1 (平文) は移行が必要', () => {
    const v1 = { version: 1, extensionVersionCounter: 3, entries };
    assert.deepEqual(getConfigStatus(v1), { initialized: false, needsMigration: true });
  });

  test('エントリが空の v1 は移行不要の未初期化として扱う', () => {
    const v1 = { version: 1, extensionVersionCounter: 0, entries: [] };
    assert.deepEqual(getConfigStatus(v1), { initialized: false, needsMigration: false });
  });

  test('entries が配列でない v1 は、空とみなさず移行が必要として扱う', () => {
    const v1 = { version: 1, extensionVersionCounter: 0, entries: { a: entries[0] } };
    assert.deepEqual(getConfigStatus(v1), { initialized: false, needsMigration: true });
  });

  test('v2 は初期化済み', async () => {
    const { config } = await makeSealed();
    assert.deepEqual(getConfigStatus(config), { initialized: true, needsMigration: false });
  });

  test('未知のバージョンはエラーにする', () => {
    assert.throws(() => getConfigStatus({ version: 99 }), UnsupportedConfigError);
    assert.throws(() => getConfigStatus({ version: 99 }), StateError);
  });

  test('新しいバージョンのエラーは「新しいバージョンで作成された可能性」を伝える', () => {
    assert.throws(() => getConfigStatus({ version: 3 }), /新しいバージョン/);
  });

  const brokenConfigs = [
    ['空のオブジェクト', {}],
    ['version が無い', { entries: [] }],
    ['version が文字列', { version: '2' }],
    ['version が小数', { version: 2.5 }],
    ['version が 0', { version: 0 }],
    ['version が負数', { version: -1 }],
    ['version が null', { version: null }],
    ['配列', [{ version: 2 }]],
    ['数値', 2],
    ['文字列', 'config'],
    ['真偽値 false', false],
    ['真偽値 true', true],
  ];
  for (const [label, config] of brokenConfigs) {
    test(`壊れた config (${label}) は BrokenConfigError にし、新しいバージョンとは報告しない`, () => {
      assert.throws(() => getConfigStatus(config), (error) => {
        assert.ok(error instanceof BrokenConfigError);
        assert.ok(error instanceof StateError);
        assert.ok(!(error instanceof UnsupportedConfigError));
        assert.doesNotMatch(error.message, /新しいバージョン/);
        assert.match(error.message, /config\.json/);
        assert.match(error.message, /壊れているか/);
        return true;
      });
    });
  }

  test('壊れた config のエラーには、渡された config のパスを含める', () => {
    const configPath = '/home/user/.config/easy-basic-auth/config.json';
    assert.throws(() => getConfigStatus({}, { configPath }), (error) => {
      assert.ok(error instanceof BrokenConfigError);
      assert.ok(error.message.includes(configPath));
      assert.equal(error.configPath, configPath);
      return true;
    });
  });
});

describe('getConfigStatus: v2 の中身の検証', () => {
  const configPath = '/home/user/.config/easy-basic-auth/config.json';

  function assertBroken(config) {
    assert.throws(() => getConfigStatus(config, { configPath }), (error) => {
      assert.ok(error instanceof BrokenConfigError);
      assert.ok(error.message.includes(configPath));
      return true;
    });
  }

  // 正しい v2 の一部を書き換えた config を作る
  async function sealedWith(change) {
    const { config } = await makeSealed();
    return change(structuredClone(config));
  }

  const brokenV2 = [
    ['extensionVersionCounter が無い', (c) => { delete c.extensionVersionCounter; return c; }],
    ['extensionVersionCounter が文字列', (c) => ({ ...c, extensionVersionCounter: '5' })],
    ['extensionVersionCounter が小数', (c) => ({ ...c, extensionVersionCounter: 1.5 })],
    ['extensionVersionCounter が負数', (c) => ({ ...c, extensionVersionCounter: -1 })],
    ['extensionVersionCounter が null', (c) => ({ ...c, extensionVersionCounter: null })],
    ['kdf が無い', (c) => { delete c.kdf; return c; }],
    ['kdf が文字列', (c) => ({ ...c, kdf: 'PBKDF2' })],
    ['kdf.iterations が無い', (c) => { delete c.kdf.iterations; return c; }],
    ['kdf.iterations が文字列', (c) => ({ ...c, kdf: { ...c.kdf, iterations: '1000' } })],
    ['kdf.iterations が 0', (c) => ({ ...c, kdf: { ...c.kdf, iterations: 0 } })],
    ['kdf.salt が無い', (c) => { delete c.kdf.salt; return c; }],
    ['kdf.salt が base64 でない', (c) => ({ ...c, kdf: { ...c.kdf, salt: '***' } })],
    ['kdf.hash が無い', (c) => { delete c.kdf.hash; return c; }],
    ['kdf.hash が未対応', (c) => ({ ...c, kdf: { ...c.kdf, hash: 'MD5' } })],
    ['kdf.name が PBKDF2 でない', (c) => ({ ...c, kdf: { ...c.kdf, name: 'scrypt' } })],
    ['vault が無い', (c) => { delete c.vault; return c; }],
    ['vault が配列', (c) => ({ ...c, vault: [] })],
    ['vault.iv が無い', (c) => { delete c.vault.iv; return c; }],
    ['vault.ciphertext が数値', (c) => ({ ...c, vault: { ...c.vault, ciphertext: 1 } })],
    ['vault.iv が base64 でない', (c) => ({ ...c, vault: { ...c.vault, iv: '!!' } })],
    ['kdf.salt が空文字', (c) => ({ ...c, kdf: { ...c.kdf, salt: '' } })],
    ['vault.iv が空文字', (c) => ({ ...c, vault: { ...c.vault, iv: '' } })],
    ['vault.ciphertext が空文字', (c) => ({ ...c, vault: { ...c.vault, ciphertext: '' } })],
    ['vault.iv の長さが短い', (c) => ({ ...c, vault: { ...c.vault, iv: bytesToBase64(new Uint8Array(IV_BYTES - 1)) } })],
    ['vault.iv の長さが長い', (c) => ({ ...c, vault: { ...c.vault, iv: bytesToBase64(new Uint8Array(IV_BYTES + 4)) } })],
  ];
  for (const [label, change] of brokenV2) {
    test(`壊れた v2 (${label}) は BrokenConfigError にする`, async () => {
      assertBroken(await sealedWith(change));
    });
  }

  test('v2 の extensionVersionCounter が 0 なら有効', async () => {
    const config = await sealedWith((c) => ({ ...c, extensionVersionCounter: 0 }));
    assert.deepEqual(getConfigStatus(config), { initialized: true, needsMigration: false });
  });

  const brokenV1Counters = [['文字列', '3'], ['小数', 1.5], ['負数', -1], ['null', null], ['オブジェクト', {}]];
  for (const [label, counter] of brokenV1Counters) {
    test(`v1 の extensionVersionCounter が ${label} の場合は BrokenConfigError にする`, () => {
      assertBroken({ version: 1, extensionVersionCounter: counter, entries });
    });
  }

  test('v1 の extensionVersionCounter が無い場合は有効 (0 とみなす)', () => {
    assert.deepEqual(getConfigStatus({ version: 1, entries }), { initialized: false, needsMigration: true });
  });
});

describe('sealConfig / openConfig', () => {
  test('v2 形式で暗号化し、平文を含まない', async () => {
    const { config } = await makeSealed();
    assert.equal(config.version, 2);
    assert.equal(config.extensionVersionCounter, 5);
    assert.ok(!JSON.stringify(config).includes('secret-p'));
    assert.ok(!JSON.stringify(config).includes('a.example.com'));
  });

  test('マスターパスワードで開くと鍵とエントリを返す', async () => {
    const { config } = await makeSealed();
    const opened = await openConfig(config, PASSWORD);
    assert.deepEqual(opened.entries, entries);
    assert.deepEqual(await readConfigEntries(config, opened.key), entries);
  });

  test('誤ったマスターパスワードでは DecryptionError になる', async () => {
    const { config } = await makeSealed();
    await assert.rejects(openConfig(config, 'wrong password!!'), DecryptionError);
  });
});
