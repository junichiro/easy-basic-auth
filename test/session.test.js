import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createSession, LockedError } from '../src/session.js';

function createClock(start = 0) {
  let current = start;
  return { now: () => current, advance: (ms) => { current += ms; } };
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
});
