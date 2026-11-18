import { deriveKey, decryptJson, VAULT_AAD, DecryptionError } from './vault-crypto.js';
import { buildRules } from './rules.js';
import { createMutex } from './mutex.js';

export const LOCKED_BADGE_TEXT = 'LOCK';
const LOCKED_BADGE_COLOR = '#8a8886';
const UNLOCKED_STORAGE_KEY = 'unlocked';
const ENTRY_COUNT_STORAGE_KEY = 'entryCount';
const STALE_EXTENSION_MESSAGE = '設定が更新されています。edge://extensions で拡張機能を再読み込みしてから解除してください';

/**
 * vault を復号してセッションルール (メモリのみ・ブラウザ終了で消える) を登録する。
 * chrome.* API は引数で受け取り、テストではフェイクに差し替える。
 *
 * @param {object} deps
 * @param {object} deps.dnr chrome.declarativeNetRequest
 * @param {object} deps.storage chrome.storage.session (メモリのみ)
 * @param {object} deps.action chrome.action
 * @param {() => Promise<object>} deps.loadVault vault.json を読み込む関数
 * @param {string} deps.manifestVersion 動作中の拡張機能の version (chrome.runtime.getManifest().version)
 */
export function createUnlocker({ dnr, storage, action, loadVault, manifestVersion }) {
  // ルールの読み出しと置き換えの間に別の解除・ロックが割り込まないよう、順番に実行する
  const exclusive = createMutex();

  async function isUnlocked() {
    const items = await storage.get(UNLOCKED_STORAGE_KEY);
    return items[UNLOCKED_STORAGE_KEY] === true;
  }

  // entryCount: 解除時に登録した有効なエントリの数。0 件ならポップアップでその旨を案内する
  async function setUnlocked(unlocked, entryCount = 0) {
    await storage.set({ [UNLOCKED_STORAGE_KEY]: unlocked, [ENTRY_COUNT_STORAGE_KEY]: entryCount });
    await refreshBadge();
  }

  async function getStatus() {
    const items = await storage.get([UNLOCKED_STORAGE_KEY, ENTRY_COUNT_STORAGE_KEY]);
    if (items[UNLOCKED_STORAGE_KEY] !== true) return { unlocked: false };
    return { unlocked: true, entryCount: items[ENTRY_COUNT_STORAGE_KEY] ?? 0 };
  }

  async function replaceSessionRules(rules) {
    const existing = await dnr.getSessionRules();
    await dnr.updateSessionRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: rules,
    });
  }

  async function refreshBadge() {
    const unlocked = await isUnlocked();
    await action.setBadgeText({ text: unlocked ? '' : LOCKED_BADGE_TEXT });
    if (!unlocked) await action.setBadgeBackgroundColor({ color: LOCKED_BADGE_COLOR });
  }

  // vault.json はディスクから毎回読まれるが、manifest (host_permissions) は再読み込みまで古いまま。
  // 食い違ったまま解除すると、新しいドメインにヘッダーが付かないので解除しない。
  // version を記録していない古い vault は確認できないため通す
  function isStaleExtension(vault) {
    return vault.extensionVersion !== undefined && vault.extensionVersion !== manifestVersion;
  }

  // 前回の解除で登録したルールが残ると、設定 UI で無効化・削除したエントリの認証情報が送られ続ける。
  // 解除を断るときはロック状態にもする (exclusive の中で呼ばれるので、公開の lock ではなく内部の lock を使う)
  async function refuseStaleExtension() {
    await lock();
    return { ok: false, error: STALE_EXTENSION_MESSAGE };
  }

  async function decryptEntries(password, vault) {
    const key = await deriveKey(password, vault.kdf);
    const { entries } = await decryptJson(key, vault, VAULT_AAD.extension);
    return entries;
  }

  async function unlock(password) {
    const vault = await loadVault();
    if (isStaleExtension(vault)) return refuseStaleExtension();
    let entries;
    try {
      entries = await decryptEntries(password, vault);
    } catch (error) {
      if (error instanceof DecryptionError) return { ok: false, error: 'マスターパスワードが違います' };
      throw error;
    }
    const rules = buildRules(entries);
    await replaceSessionRules(rules);
    await setUnlocked(true, entries.length);
    return { ok: true, ruleCount: rules.length };
  }

  async function lock() {
    await replaceSessionRules([]);
    await setUnlocked(false);
  }

  // 無効化→有効化や再読み込みでは storage.session は消えるが、セッションルールは残ることがある。
  // 解除の状態が残っていなければ、ルールも消してロックの表示と実際の動作をそろえる
  async function syncLockState() {
    if (await isUnlocked()) {
      await refreshBadge();
      return;
    }
    await lock();
  }

  return {
    getStatus,
    unlock: (password) => exclusive(() => unlock(password)),
    lock: () => exclusive(lock),
    syncLockState: () => exclusive(syncLockState),
    refreshBadge,
  };
}

/**
 * popup からのメッセージを処理する。自分自身の拡張機能以外からは受け付けない。
 */
export function createMessageHandler(unlocker, extensionId) {
  const handlers = {
    status: () => unlocker.getStatus(),
    unlock: (message) => unlocker.unlock(String(message.password ?? '')),
    lock: async () => {
      await unlocker.lock();
      return { ok: true };
    },
  };

  return async (message, sender) => {
    if (sender?.id !== extensionId) return { ok: false, error: 'Unauthorized sender' };
    const handler = handlers[message?.type];
    if (!handler) return { ok: false, error: `Unknown message type: ${message?.type}` };
    try {
      return await handler(message);
    } catch (error) {
      console.error('[edge-basic-auth]', error);
      return { ok: false, error: `処理に失敗しました: ${error.message}` };
    }
  };
}
