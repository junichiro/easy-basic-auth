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
 * 一定時間使われなければ破棄する。API へのアクセスがなくても破棄されるようタイマーを使い、
 * アクセス時にも経過時間を判定する（タイマーが遅れた場合や now を差し替えたテストのため）。
 */
export function createSession({
  idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
} = {}) {
  let key = null;
  let lastAccessAt = 0;
  let lockReason = null;
  // lock() のたびに増える。解除処理の開始後にロックされたかを判定するために使う
  let lockCount = 0;
  let idleTimer = null;

  function cancelIdleTimer() {
    if (idleTimer === null) return;
    clearTimer(idleTimer);
    idleTimer = null;
  }

  function expire() {
    cancelIdleTimer();
    key = null;
    lockReason = IDLE_LOCK_MESSAGE;
  }

  // 最終アクセスから idleTimeoutMs 後に鍵を破棄するタイマーを張り直す
  function scheduleIdleTimer() {
    cancelIdleTimer();
    idleTimer = setTimer(expire, idleTimeoutMs);
    // タイマーのせいでプロセスが終了できなくならないようにする
    idleTimer?.unref?.();
  }

  function touch() {
    lastAccessAt = now();
    scheduleIdleTimer();
  }

  function expireIfIdle() {
    if (!key || now() - lastAccessAt <= idleTimeoutMs) return;
    expire();
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
      lockReason = null;
      touch();
      return true;
    },
    lock() {
      cancelIdleTimer();
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
      touch();
      return key;
    },
  };
}
