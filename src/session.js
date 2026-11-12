export const DEFAULT_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const IDLE_LOCK_MESSAGE = '一定時間操作がなかったためロックしました。マスターパスワードで解除してください';

export class LockedError extends Error {
  constructor(message = 'ロックされています。マスターパスワードで解除してください') {
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
  let lockReason = null;
  // lock() のたびに増える。解除処理の開始後にロックされたかを判定するために使う
  let lockCount = 0;

  function expireIfIdle() {
    if (!key || now() - lastAccessAt <= idleTimeoutMs) return;
    key = null;
    lockReason = IDLE_LOCK_MESSAGE;
  }

  return {
    /** 解除処理の開始時に取得し、unlock() に渡す */
    ticket() {
      return lockCount;
    },
    /**
     * 鍵を保持してアンロックする。ticket の取得後に lock() されていれば何もしない。
     * @returns {boolean} アンロックしたかどうか
     */
    unlock(newKey, ticket = lockCount) {
      if (ticket !== lockCount) return false;
      key = newKey;
      lastAccessAt = now();
      lockReason = null;
      return true;
    },
    lock() {
      key = null;
      lockReason = null;
      lockCount += 1;
    },
    isUnlocked() {
      expireIfIdle();
      return key !== null;
    },
    getKey() {
      expireIfIdle();
      if (!key) throw new LockedError(lockReason ?? undefined);
      lastAccessAt = now();
      return key;
    },
  };
}
