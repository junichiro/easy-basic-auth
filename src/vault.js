import { deriveKey, encryptJson, decryptJson, VAULT_AAD } from './extension/lib/vault-crypto.js';
import { StateError } from './errors.js';

const LEGACY_VERSION = 1;
export const CONFIG_VERSION = 2;

export class UnsupportedConfigError extends StateError {
  constructor(version) {
    super(`未対応の config.json のバージョンです (version: ${version})。新しいバージョンのツールで作成された可能性があります`);
    this.name = 'UnsupportedConfigError';
  }
}

// config.json が壊れている、または想定した形式ではない (オブジェクトでない、version が正の整数でない)
export class BrokenConfigError extends StateError {
  constructor({ configPath } = {}) {
    const location = configPath ? ` (${configPath})` : '';
    super(`config.json${location} が壊れているか、想定した形式ではありません。ファイルを修正するか、別の場所へ移動してから再度お試しください`);
    this.name = 'BrokenConfigError';
    this.configPath = configPath;
  }
}

function isPlainObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isValidVersion(version) {
  return Number.isInteger(version) && version >= LEGACY_VERSION;
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
 * - オブジェクトでない、または version が正の整数でない: BrokenConfigError
 *   (configPath を渡すと、エラーメッセージにファイルの場所を含める)
 */
export function getConfigStatus(config, { configPath } = {}) {
  if (config === null || config === undefined) return { initialized: false, needsMigration: false };
  if (!isPlainObject(config) || !isValidVersion(config.version)) throw new BrokenConfigError({ configPath });
  if (config.version === CONFIG_VERSION) return { initialized: true, needsMigration: false };
  if (config.version === LEGACY_VERSION) {
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
