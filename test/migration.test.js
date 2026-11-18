import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeLegacyEntries } from '../src/migration.js';
import { ValidationError } from '../src/entries.js';

const CONFIG_PATH = '/home/user/.easy-basic-auth/config.json';

function normalize(entries) {
  let counter = 0;
  return normalizeLegacyEntries(entries, { generateId: () => `gen-${++counter}`, configPath: CONFIG_PATH });
}

describe('normalizeLegacyEntries', () => {
  test('正しいエントリは新規登録と同じ形に正規化される', () => {
    const [entry] = normalize([{ id: '1', domain: 'a.example.com', username: 'u', password: 'p' }]);
    assert.equal(entry.id, '1');
    assert.equal(entry.domain, 'a.example.com');
  });

  test('旧形式のエントリは https のみ (allowHttp: false) として移行する', () => {
    const [entry] = normalize([{ id: '1', domain: 'a.example.com', username: 'u', password: 'p' }]);
    assert.equal(entry.allowHttp, false);
  });

  test('entries がオブジェクトの場合は TypeError ではなく ValidationError になる', () => {
    assert.throws(() => normalize({ a: { domain: 'a.example.com' } }), ValidationError);
  });

  test('entries が配列でない場合のエラーには原因と config.json の場所が含まれる', () => {
    assert.throws(() => normalize('broken'), (error) => {
      assert.match(error.message, /entries/);
      assert.match(error.message, /配列/);
      assert.ok(error.message.includes(CONFIG_PATH));
      return true;
    });
  });
});
