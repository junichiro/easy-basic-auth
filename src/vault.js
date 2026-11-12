import { deriveKey, encryptJson, decryptJson, VAULT_AAD } from './extension/lib/vault-crypto.js';

const LEGACY_VERSION = 1;
export const CONFIG_VERSION = 2;

export class UnsupportedConfigError extends Error {
  constructor(version) {
    super(`未対応の config.json のバージョンです (version: ${version})。新しいバージョンのツールで作成された可能性があります`);
    this.name = 'UnsupportedConfigError';
  }
}

/**
 * config.json の状態を判定する。
 * - v1: 旧形式（平文）。エントリがあれば移行が必要
 * - v2: マスターパスワードで暗号化済み
 */
export function getConfigStatus(config) {
  if (!config) return { initialized: false, needsMigration: false };
  if (config.version === CONFIG_VERSION) return { initialized: true, needsMigration: false };
  if (config.version === LEGACY_VERSION) {
    return { initialized: false, needsMigration: (config.entries ?? []).length > 0 };
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
