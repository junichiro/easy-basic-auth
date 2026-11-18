import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createSession, LockedError } from '../src/session.js';

function createClock(start = 0) {
  let current = start;
  return { now: () => current, advance: (ms) => { current += ms; } };
}

// 時計と連動する偽タイマー。advance() で期限が来たタイマーを発火させる
function createFakeTimers(start = 0) {
  let current = start;
  const timers = new Set();
  return {
    now: () => current,
    setTimer(fn, ms) {
      const timer = { fn, at: current + ms, unrefCalled: false, unref() { this.unrefCalled = true; return this; } };
      timers.add(timer);
      return timer;
    },
    clearTimer(timer) {
      timers.delete(timer);
    },
    pendingCount: () => timers.size,
    pending: () => [...timers],
    advance(ms) {
      current += ms;
      for (const timer of [...timers]) {
        if (timer.at > current) continue;
        timers.delete(timer);
        timer.fn();
      }
    },
  };
}

describe('createSession', () => {
  const IDLE = 15 * 60 * 1000;

  test('初期状態はロック中', () => {
    const session = createSession({ idleTimeoutMs: IDLE });
    assert.equal(session.isUnlocked(), false);
    assert.throws(() => session.getKey(), LockedError);
  });

  test('アンロックすると鍵を取得できる', () => {
    const session = createSession({ idleTimeoutMs: IDLE });
    session.unlock('KEY');
    assert.equal(session.isUnlocked(), true);
    assert.equal(session.getKey(), 'KEY');
  });

  test('ロックすると鍵を破棄する', () => {
    const session = createSession({ idleTimeoutMs: IDLE });
    session.unlock('KEY');
    session.lock();
    assert.throws(() => session.getKey(), LockedError);
  });

  test('ticket を取得した後にロックされたら、unlock は無視される', () => {
    const session = createSession({ idleTimeoutMs: IDLE });
    const ticket = session.ticket();
    session.lock();
    assert.equal(session.unlock('KEY', ticket), false);
    assert.equal(session.isUnlocked(), false);
  });

  test('一定時間操作がなければ自動でロックする', () => {
    const clock = createClock();
    const session = createSession({ idleTimeoutMs: IDLE, now: clock.now });
    session.unlock('KEY');
    clock.advance(IDLE + 1);
    assert.throws(() => session.getKey(), /一定時間操作がなかった/);
    assert.equal(session.isUnlocked(), false);
  });

  test('鍵を使うたびに自動ロックまでの時間を延長する', () => {
    const clock = createClock();
    const session = createSession({ idleTimeoutMs: IDLE, now: clock.now });
    session.unlock('KEY');
    clock.advance(IDLE - 1);
    session.getKey();
    clock.advance(IDLE - 1);
    assert.equal(session.getKey(), 'KEY');
  });

  describe('アクセスがなくてもタイマーで自動ロックする', () => {
    function createTimedSession() {
      const timers = createFakeTimers();
      const session = createSession({
        idleTimeoutMs: IDLE,
        now: timers.now,
        setTimer: (fn, ms) => timers.setTimer(fn, ms),
        clearTimer: (timer) => timers.clearTimer(timer),
      });
      return { timers, session };
    }

    test('アンロック後、アクセスがなくてもタイマーの発火で鍵を破棄する', () => {
      const { timers, session } = createTimedSession();
      session.unlock('KEY');
      assert.equal(timers.pendingCount(), 1);
      timers.advance(IDLE);
      assert.equal(timers.pendingCount(), 0);
      // 発火後に初めてアクセスする（アクセス時判定ではなくタイマーで破棄されていること）
      assert.throws(() => session.getKey(), /一定時間操作がなかった/);
      assert.equal(session.isUnlocked(), false);
    });

    test('期限前に鍵を使うと、タイマーの期限が延びる', () => {
      const { timers, session } = createTimedSession();
      session.unlock('KEY');
      timers.advance(IDLE - 1);
      session.getKey();
      timers.advance(IDLE - 1);
      assert.equal(timers.pendingCount(), 1);
      assert.equal(session.getKey(), 'KEY');
      timers.advance(IDLE);
      assert.throws(() => session.getKey(), /一定時間操作がなかった/);
    });

    test('ロックするとタイマーを解除する', () => {
      const { timers, session } = createTimedSession();
      session.unlock('KEY');
      session.lock();
      assert.equal(timers.pendingCount(), 0);
    });

    test('タイマーはプロセスを生かし続けないよう unref される', () => {
      const { timers, session } = createTimedSession();
      session.unlock('KEY');
      assert.equal(timers.pending()[0].unrefCalled, true);
    });

    test('アンロックし直すとタイマーは 1 つだけ残る', () => {
      const { timers, session } = createTimedSession();
      session.unlock('KEY');
      session.unlock('KEY2');
      assert.equal(timers.pendingCount(), 1);
    });
  });
});
