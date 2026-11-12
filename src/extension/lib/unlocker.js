import { deriveKey, decryptJson, VAULT_AAD, DecryptionError } from './vault-crypto.js';
import { buildRules } from './rules.js';

export const LOCKED_BADGE_TEXT = 'LOCK';
const LOCKED_BADGE_COLOR = '#8a8886';
const UNLOCKED_STORAGE_KEY = 'unlocked';

/**
 * vault を復号してセッションルール (メモリのみ・ブラウザ終了で消える) を登録する。
 * chrome.* API は引数で受け取り、テストではフェイクに差し替える。
 *
 * @param {object} deps
 * @param {object} deps.dnr chrome.declarativeNetRequest
 * @param {object} deps.storage chrome.storage.session (メモリのみ)
 * @param {object} deps.action chrome.action
 * @param {() => Promise<object>} deps.loadVault vault.json を読み込む関数
 */
export function createUnlocker({ dnr, storage, action, loadVault }) {
  async function isUnlocked() {
    const items = await storage.get(UNLOCKED_STORAGE_KEY);
    return items[UNLOCKED_STORAGE_KEY] === true;
  }

  async function setUnlocked(unlocked) {
    await storage.set({ [UNLOCKED_STORAGE_KEY]: unlocked });
    await refreshBadge();
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

  async function decryptEntries(password) {
    const vault = await loadVault();
    const key = await deriveKey(password, vault.kdf);
    const { entries } = await decryptJson(key, vault, VAULT_AAD.extension);
    return entries;
  }

  async function unlock(password) {
    let entries;
    try {
      entries = await decryptEntries(password);
    } catch (error) {
      if (error instanceof DecryptionError) return { ok: false, error: 'マスターパスワードが違います' };
      throw error;
    }
    const rules = buildRules(entries);
    await replaceSessionRules(rules);
    await setUnlocked(true);
    return { ok: true, ruleCount: rules.length };
  }

  async function lock() {
    await replaceSessionRules([]);
    await setUnlocked(false);
  }

  return {
    getStatus: async () => ({ unlocked: await isUnlocked() }),
    unlock,
    lock,
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
