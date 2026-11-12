// Node と拡張機能の両方で使うため、WebCrypto (globalThis.crypto) とブラウザ互換 API だけを使う

export const DEFAULT_KDF_ITERATIONS = 2000000;
const SALT_BYTES = 16;
const IV_BYTES = 12;

// 暗号文の用途。設定ファイルと拡張機能の暗号文を取り違えて復号できないようにする
export const VAULT_AAD = Object.freeze({
  config: 'edge-basic-auth/config/v2',
  extension: 'edge-basic-auth/extension/v1',
});

export class DecryptionError extends Error {
  constructor(message = 'Failed to decrypt vault (wrong password or corrupted data)') {
    super(message);
    this.name = 'DecryptionError';
  }
}

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function bytesToBase64(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (char) => char.charCodeAt(0));
}

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

export function createKdfParams({ iterations = DEFAULT_KDF_ITERATIONS } = {}) {
  return {
    name: 'PBKDF2',
    hash: 'SHA-256',
    iterations,
    salt: bytesToBase64(randomBytes(SALT_BYTES)),
  };
}

/**
 * マスターパスワードから取り出し不可能な AES-256-GCM 鍵を導出する。
 */
export async function deriveKey(password, kdf) {
  const baseKey = await crypto.subtle.importKey(
    'raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveKey'],
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', hash: kdf.hash, iterations: kdf.iterations, salt: base64ToBytes(kdf.salt) },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptJson(key, value, aad) {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: textEncoder.encode(aad) },
    key,
    textEncoder.encode(JSON.stringify(value)),
  );
  return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
}

export async function decryptJson(key, { iv, ciphertext }, aad) {
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(iv), additionalData: textEncoder.encode(aad) },
      key,
      base64ToBytes(ciphertext),
    );
  } catch {
    // GCM の認証タグ不一致 = パスワード違い、または改ざん
    throw new DecryptionError();
  }
  return JSON.parse(textDecoder.decode(plaintext));
}
