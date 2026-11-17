import {
  deriveKey, encryptJson, decryptJson, base64ToBytes, VAULT_AAD, IV_BYTES, DEFAULT_KDF_ITERATIONS,
} from './extension/lib/vault-crypto.js';
import { StateError, BrokenConfigError } from './errors.js';

const LEGACY_VERSION = 1;
export const CONFIG_VERSION = 2;

export class UnsupportedConfigError extends StateError {
  constructor(version) {
    super(`未対応の config.json のバージョンです (version: ${version})。新しいバージョンのツールで作成された可能性があります`);
    this.name = 'UnsupportedConfigError';
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidVersion(version) {
  return Number.isInteger(version) && version >= LEGACY_VERSION;
}

const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const SUPPORTED_KDF_HASHES = new Set(['SHA-256', 'SHA-384', 'SHA-512']);
// 将来の既定値の引き上げに余裕を持たせつつ、WebCrypto が受け付けない値や、
// 解除に何分もかかる (その間、保存も待たされる) 値は壊れた config として扱う
const MAX_KDF_ITERATIONS = DEFAULT_KDF_ITERATIONS * 50;
// AES-GCM の暗号文は、少なくとも認証タグ (16 バイト) を含む
const GCM_TAG_BYTES = 16;

function isNonNegativeInteger(value) {
  return Number.isInteger(value) && value >= 0;
}

// 空文字は BASE64_PATTERN に一致してしまうため、空でない base64 だけを有効とする
function isNonEmptyBase64(value) {
  return typeof value === 'string' && value !== '' && BASE64_PATTERN.test(value);
}

// encryptJson が作る長さの IV か
function isValidIv(value) {
  return isNonEmptyBase64(value) && base64ToBytes(value).length === IV_BYTES;
}

// deriveKey に渡せる形か (createKdfParams が作る形)
function isValidKdf(kdf) {
  if (!isPlainObject(kdf)) return false;
  if (kdf.name !== 'PBKDF2' || !SUPPORTED_KDF_HASHES.has(kdf.hash)) return false;
  return isValidKdfIterations(kdf.iterations) && isNonEmptyBase64(kdf.salt);
}

function isValidKdfIterations(iterations) {
  return Number.isInteger(iterations) && iterations > 0 && iterations <= MAX_KDF_ITERATIONS;
}

// 短すぎる暗号文は復号で必ず失敗し、「マスターパスワードが違います」と区別できないため、ここで弾く
function isValidCiphertext(value) {
  return isNonEmptyBase64(value) && base64ToBytes(value).length >= GCM_TAG_BYTES;
}

// decryptJson に渡せる形か (encryptJson が作る形)
function isValidSealedVault(vault) {
  return isPlainObject(vault) && isValidIv(vault.iv) && isValidCiphertext(vault.ciphertext);
}

function isValidV2Config(config) {
  return isNonNegativeInteger(config.extensionVersionCounter)
    && isValidKdf(config.kdf)
    && isValidSealedVault(config.vault);
}

// v1 の extensionVersionCounter は省略可 (0 とみなす)。あれば 0 以上の整数でなければならない
function isValidLegacyConfig(config) {
  return config.extensionVersionCounter === undefined || isNonNegativeInteger(config.extensionVersionCounter);
}

// 旧形式のエントリがあるか。配列でない値 (手編集・破損) も空とはみなさず、
// 移行時の検証 (normalizeLegacyEntries) でエラーとして報告させる
function hasLegacyEntries(entries) {
  if (entries === undefined || entries === null) return false;
  if (!Array.isArray(entries)) return true;
  return entries.length > 0;
}

/**
 * config.json の状態を判定する。
 * - v1: 旧形式（平文）。エントリがあれば移行が必要
 * - v2: マスターパスワードで暗号化済み
 * - それより新しい整数の version: UnsupportedConfigError
 * - オブジェクトでない、version が正の整数でない、または v1/v2 の中身が想定した形でない: BrokenConfigError
 *   (configPath を渡すと、エラーメッセージにファイルの場所を含める)
 */
export function getConfigStatus(config, { configPath } = {}) {
  if (config === null || config === undefined) return { initialized: false, needsMigration: false };
  if (!isPlainObject(config) || !isValidVersion(config.version)) throw new BrokenConfigError({ configPath });
  if (config.version === CONFIG_VERSION) {
    if (!isValidV2Config(config)) throw new BrokenConfigError({ configPath });
    return { initialized: true, needsMigration: false };
  }
  if (config.version === LEGACY_VERSION) {
    if (!isValidLegacyConfig(config)) throw new BrokenConfigError({ configPath });
    return { initialized: false, needsMigration: hasLegacyEntries(config.entries) };
  }
  throw new UnsupportedConfigError(config.version);
}

export function getLegacyEntries(config) {
  return config?.version === LEGACY_VERSION ? config.entries ?? [] : [];
}

export async function sealConfig({ counter, kdf, key, entries }) {
  return {
    version: CONFIG_VERSION,
    extensionVersionCounter: counter,
    kdf,
    vault: await encryptJson(key, { entries }, VAULT_AAD.config),
  };
}

export async function readConfigEntries(config, key) {
  const { entries } = await decryptJson(key, config.vault, VAULT_AAD.config);
  return entries;
}

/**
 * マスターパスワードで config を開く。パスワードが違えば DecryptionError を投げる。
 */
export async function openConfig(config, masterPassword) {
  const key = await deriveKey(masterPassword, config.kdf);
  return { key, entries: await readConfigEntries(config, key) };
}
