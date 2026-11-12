export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;

export class LockedError extends Error {
  constructor(message = 'Vault is locked') {
    super(message);
    this.name = 'LockedError';
  }
}

/**
 * 設定 UI のロック状態を管理する。導出した鍵はメモリ上にだけ保持し、
 * 一定時間使われなければ破棄する（タイマーではなくアクセス時に判定する）。
 */
export function createSession({ idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS, now = Date.now } = {}) {
  let key = null;
  let lastAccessAt = 0;

  function expireIfIdle() {
    if (key && now() - lastAccessAt > idleTimeoutMs) key = null;
  }

  return {
    unlock(newKey) {
      key = newKey;
      lastAccessAt = now();
    },
    lock() {
      key = null;
    },
    isUnlocked() {
      expireIfIdle();
      return key !== null;
    },
    getKey() {
      expireIfIdle();
      if (!key) throw new LockedError();
      lastAccessAt = now();
      return key;
    },
  };
}
