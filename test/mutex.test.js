import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { createMutex } from '../src/extension/lib/mutex.js';

describe('createMutex', () => {
  test('受け付けた順に 1 つずつ実行する', async () => {
    const exclusive = createMutex();
    const order = [];
    const slow = exclusive(async () => {
      await new Promise((resolve) => setImmediate(resolve));
      order.push('slow');
    });
    const fast = exclusive(async () => { order.push('fast'); });
    await Promise.all([slow, fast]);
    assert.deepEqual(order, ['slow', 'fast']);
  });

  test('前の処理が失敗しても、後の処理は実行する', async () => {
    const exclusive = createMutex();
    const failed = exclusive(async () => { throw new Error('boom'); });
    await assert.rejects(failed, /boom/);
    assert.equal(await exclusive(async () => 'ok'), 'ok');
  });

  test('前の処理の戻り値を、次の処理の引数に渡さない', async () => {
    const exclusive = createMutex();
    await exclusive(async () => 'previous result');
    const args = await exclusive(async (...received) => received);
    assert.deepEqual(args, []);
  });
});
