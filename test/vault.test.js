import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { getConfigStatus, sealConfig, openConfig, readConfigEntries, UnsupportedConfigError } from '../src/vault.js';
import { createKdfParams, deriveKey, DecryptionError } from '../src/extension/lib/vault-crypto.js';
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

  test('v2 は初期化済み', async () => {
    const { config } = await makeSealed();
    assert.deepEqual(getConfigStatus(config), { initialized: true, needsMigration: false });
  });

  test('未知のバージョンはエラーにする', () => {
    assert.throws(() => getConfigStatus({ version: 99 }), UnsupportedConfigError);
    assert.throws(() => getConfigStatus({ version: 99 }), StateError);
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
