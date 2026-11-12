import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_KDF_ITERATIONS,
  VAULT_AAD,
  createKdfParams,
  deriveKey,
  encryptJson,
  decryptJson,
  bytesToBase64,
  base64ToBytes,
  DecryptionError,
} from '../src/extension/lib/vault-crypto.js';

// テスト高速化のため反復回数を下げる
const ITERATIONS = 1000;
const PASSWORD = 'correct horse battery staple';

describe('createKdfParams', () => {
  test('PBKDF2-SHA256 と 16 バイトのランダムな salt を使う', () => {
    const kdf = createKdfParams({ iterations: ITERATIONS });
    assert.equal(kdf.name, 'PBKDF2');
    assert.equal(kdf.hash, 'SHA-256');
    assert.equal(kdf.iterations, ITERATIONS);
    assert.equal(base64ToBytes(kdf.salt).length, 16);
    assert.notEqual(createKdfParams().salt, kdf.salt);
  });

  test('既定の反復回数は 2,000,000 回', () => {
    assert.equal(DEFAULT_KDF_ITERATIONS, 2000000);
    assert.equal(createKdfParams().iterations, 2000000);
  });
});

describe('bytesToBase64 / base64ToBytes', () => {
  test('すべてのバイト値を往復変換できる', () => {
    const bytes = Uint8Array.from({ length: 256 }, (_, i) => i);
    assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  });
});

describe('deriveKey', () => {
  test('取り出し不可能な AES-GCM 鍵を導出する', async () => {
    const key = await deriveKey(PASSWORD, createKdfParams({ iterations: ITERATIONS }));
    assert.equal(key.extractable, false);
    assert.equal(key.algorithm.name, 'AES-GCM');
    assert.equal(key.algorithm.length, 256);
  });
});

describe('encryptJson / decryptJson', () => {
  const kdf = createKdfParams({ iterations: ITERATIONS });
  const value = { entries: [{ username: 'ユーザー', password: 'パス🔑' }] };

  test('暗号化した値を同じパスワードで復号できる', async () => {
    const key = await deriveKey(PASSWORD, kdf);
    const sealed = await encryptJson(key, value, VAULT_AAD.config);
    assert.deepEqual(await decryptJson(key, sealed, VAULT_AAD.config), value);
  });

  test('暗号文に平文が含まれない', async () => {
    const key = await deriveKey(PASSWORD, kdf);
    const sealed = await encryptJson(key, { secret: 'plain-secret' }, VAULT_AAD.config);
    assert.ok(!JSON.stringify(sealed).includes('plain-secret'));
  });

  test('同じ値でも毎回異なる IV と暗号文になる', async () => {
    const key = await deriveKey(PASSWORD, kdf);
    const a = await encryptJson(key, value, VAULT_AAD.config);
    const b = await encryptJson(key, value, VAULT_AAD.config);
    assert.equal(base64ToBytes(a.iv).length, 12);
    assert.notEqual(a.iv, b.iv);
    assert.notEqual(a.ciphertext, b.ciphertext);
  });

  test('誤ったパスワードでは DecryptionError になる', async () => {
    const sealed = await encryptJson(await deriveKey(PASSWORD, kdf), value, VAULT_AAD.config);
    const wrongKey = await deriveKey('wrong password!!', kdf);
    await assert.rejects(decryptJson(wrongKey, sealed, VAULT_AAD.config), DecryptionError);
  });

  test('用途 (AAD) が違う暗号文は復号できない', async () => {
    const key = await deriveKey(PASSWORD, kdf);
    const sealed = await encryptJson(key, value, VAULT_AAD.config);
    await assert.rejects(decryptJson(key, sealed, VAULT_AAD.extension), DecryptionError);
  });

  test('改ざんされた暗号文は復号できない', async () => {
    const key = await deriveKey(PASSWORD, kdf);
    const sealed = await encryptJson(key, value, VAULT_AAD.config);
    const bytes = base64ToBytes(sealed.ciphertext);
    bytes[0] ^= 0xff;
    await assert.rejects(
      decryptJson(key, { ...sealed, ciphertext: bytesToBase64(bytes) }, VAULT_AAD.config),
      DecryptionError,
    );
  });
});
