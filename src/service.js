import crypto from 'node:crypto';
import { readConfig, writeConfig, getExtensionDir } from './config.js';
import { buildManifest, buildExtensionVault, writeExtension, formatExtensionVersion } from './generate.js';
import { createEntry, updateEntry, toPublicEntry, ValidationError } from './entries.js';
import { validateMasterPassword, MIN_MASTER_PASSWORD_LENGTH } from './master-password.js';
import { LockedError } from './session.js';
import { getConfigStatus, getLegacyEntries, sealConfig, openConfig, readConfigEntries } from './vault.js';
import { createKdfParams, deriveKey, DecryptionError } from './extension/lib/vault-crypto.js';

export class NotFoundError extends Error {
  constructor(message) {
    super(message);
    this.name = 'NotFoundError';
  }
}

// 初期設定済み/未設定など、現在の状態では実行できない操作
export class StateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateError';
  }
}

function assertUniqueDomain(entries, candidate) {
  const duplicate = entries.find((entry) => entry.id !== candidate.id && entry.domain === candidate.domain);
  if (duplicate) {
    throw new ValidationError(`${candidate.domain} は既に登録されています（${duplicate.label}）`, 'domain');
  }
}

function findEntryIndex(entries, id) {
  const index = entries.findIndex((entry) => entry.id === id);
  if (index === -1) throw new NotFoundError(`Entry not found: ${id}`);
  return index;
}

// 非同期の書き込み処理が交互に実行されて更新が失われないよう、順番に実行する
function createMutex() {
  let tail = Promise.resolve();
  return (task) => {
    const run = tail.then(task);
    tail = run.catch(() => {});
    return run;
  };
}

/**
 * エントリの CRUD、マスターパスワードによる暗号化、拡張機能の生成をまとめるアプリケーションサービス。
 * 設定を保存するたびに拡張機能も再生成する。
 */
export function createEntryService({ configDir, session, generateId = crypto.randomUUID, kdfIterations }) {
  const extensionDir = getExtensionDir(configDir);
  const exclusive = createMutex();

  function toState(entries, counter) {
    return {
      entries: entries.map(toPublicEntry),
      configDir,
      extensionDir,
      extensionVersion: counter > 0 ? formatExtensionVersion(counter) : null,
    };
  }

  function requireInitializedConfig() {
    const config = readConfig(configDir);
    if (!getConfigStatus(config).initialized) throw new StateError('マスターパスワードが設定されていません');
    return config;
  }

  async function persist({ counter, kdf, key, entries }) {
    const nextCounter = counter + 1;
    const config = await sealConfig({ counter: nextCounter, kdf, key, entries });
    const vault = await buildExtensionVault(entries, key, kdf);
    writeConfig(configDir, config);
    writeExtension(extensionDir, { manifest: buildManifest(entries, nextCounter), vault });
    return toState(entries, nextCounter);
  }

  async function openWithPassword(config, password, field) {
    try {
      return await openConfig(config, typeof password === 'string' ? password : '');
    } catch (error) {
      if (error instanceof DecryptionError) throw new ValidationError('マスターパスワードが違います', field);
      throw error;
    }
  }

  async function createKeyFor(masterPassword) {
    const kdf = createKdfParams({ iterations: kdfIterations });
    return { kdf, key: await deriveKey(masterPassword, kdf) };
  }

  // 別プロセスでマスターパスワードが変更されるなどして鍵が合わなければ、ロック扱いにする
  async function readUnlocked() {
    const key = session.getKey();
    const config = requireInitializedConfig();
    try {
      return { config, key, entries: await readConfigEntries(config, key) };
    } catch (error) {
      if (!(error instanceof DecryptionError)) throw error;
      session.lock();
      throw new LockedError('マスターパスワードが変更されたため、ロックしました');
    }
  }

  function mutate(changeEntries) {
    return exclusive(async () => {
      const { config, key, entries } = await readUnlocked();
      return persist({ counter: config.extensionVersionCounter, kdf: config.kdf, key, entries: changeEntries(entries) });
    });
  }

  function getStatus() {
    const { initialized, needsMigration } = getConfigStatus(readConfig(configDir));
    return {
      initialized,
      unlocked: initialized && session.isUnlocked(),
      needsMigration,
      minMasterPasswordLength: MIN_MASTER_PASSWORD_LENGTH,
    };
  }

  // 旧形式のエントリも新規登録と同じ検証・正規化を通す（ID と enabled は補完する）
  function normalizeLegacyEntries(entries) {
    return entries.map((entry) => {
      try {
        return createEntry(entry, () => entry.id || generateId());
      } catch (error) {
        if (!(error instanceof ValidationError)) throw error;
        const name = entry.label || entry.domain || '名前なし';
        throw new ValidationError(`移行できない登録があります（${name}）: ${error.message}`, error.field);
      }
    });
  }

  // 初期設定。旧形式 (平文) の config があれば、そのエントリを暗号化して移行する
  function setup(masterPassword) {
    return exclusive(async () => {
      validateMasterPassword(masterPassword);
      const config = readConfig(configDir);
      if (getConfigStatus(config).initialized) throw new StateError('マスターパスワードは設定済みです');

      const entries = normalizeLegacyEntries(getLegacyEntries(config));
      const { kdf, key } = await createKeyFor(masterPassword);
      const state = await persist({ counter: config?.extensionVersionCounter ?? 0, kdf, key, entries });
      session.unlock(key);
      return state;
    });
  }

  // パスワード変更と同時に実行されても古い鍵を保持しないよう、書き込みと同じ順番待ちに入れる
  function unlock(masterPassword) {
    return exclusive(async () => {
      const { key } = await openWithPassword(requireInitializedConfig(), masterPassword, 'masterPassword');
      session.unlock(key);
      return getStatus();
    });
  }

  function changeMasterPassword(currentPassword, newPassword) {
    return exclusive(async () => {
      validateMasterPassword(newPassword, 'newPassword');
      const config = requireInitializedConfig();
      const { entries } = await openWithPassword(config, currentPassword, 'currentPassword');
      const { kdf, key } = await createKeyFor(newPassword);
      const state = await persist({ counter: config.extensionVersionCounter, kdf, key, entries });
      session.unlock(key);
      return state;
    });
  }

  return {
    getStatus,
    setup,
    unlock,
    lock: () => {
      session.lock();
      return getStatus();
    },
    changeMasterPassword,

    getState: async () => {
      const { config, entries } = await readUnlocked();
      return toState(entries, config.extensionVersionCounter);
    },

    addEntry: (input) => mutate((entries) => {
      const entry = createEntry(input, generateId);
      assertUniqueDomain(entries, entry);
      return [...entries, entry];
    }),

    updateEntry: (id, input) => mutate((entries) => {
      const index = findEntryIndex(entries, id);
      const updated = updateEntry(entries[index], input);
      assertUniqueDomain(entries, updated);
      return entries.with(index, updated);
    }),

    deleteEntry: (id) => mutate((entries) => {
      findEntryIndex(entries, id);
      return entries.filter((entry) => entry.id !== id);
    }),

    regenerate: () => mutate((entries) => entries),
  };
}
