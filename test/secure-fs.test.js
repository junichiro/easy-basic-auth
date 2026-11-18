import { describe, test, mock, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeFileAtomic } from '../src/secure-fs.js';

const IS_POSIX = process.platform !== 'win32';

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'eba-secure-fs-'));
}

// fs の呼び出し順を記録する (実際の処理はそのまま行う)
function recordFsCalls(names) {
  const calls = [];
  for (const name of names) {
    const original = fs[name];
    mock.method(fs, name, (...args) => {
      calls.push(name);
      return original.apply(fs, args);
    });
  }
  return calls;
}

describe('writeFileAtomic', () => {
  afterEach(() => mock.restoreAll());

  test('内容を書き込み、一時ファイルを残さない', () => {
    const dir = makeTempDir();
    const filePath = path.join(dir, 'config.json');
    writeFileAtomic(filePath, 'hello');
    assert.equal(fs.readFileSync(filePath, 'utf8'), 'hello');
    assert.deepEqual(fs.readdirSync(dir), ['config.json']);
  });

  test('rename の前に一時ファイルの中身をディスクへ書き出す (停電で空のファイルにならないように)', () => {
    const dir = makeTempDir();
    const calls = recordFsCalls(['fsyncSync', 'renameSync']);
    writeFileAtomic(path.join(dir, 'config.json'), 'hello');
    const renameIndex = calls.indexOf('renameSync');
    assert.ok(renameIndex > 0, `calls: ${calls.join(', ')}`);
    assert.equal(calls[renameIndex - 1], 'fsyncSync');
  });

  test('POSIX では rename の後にディレクトリも書き出す (rename 自体を確定させる)', { skip: !IS_POSIX }, () => {
    const dir = makeTempDir();
    const calls = recordFsCalls(['fsyncSync', 'renameSync']);
    writeFileAtomic(path.join(dir, 'config.json'), 'hello');
    assert.equal(calls.at(-1), 'fsyncSync', `calls: ${calls.join(', ')}`);
  });

  test('書き込みに失敗したら一時ファイルを消してエラーを投げる', () => {
    const dir = makeTempDir();
    mock.method(fs, 'fsyncSync', () => { throw new Error('disk error'); });
    assert.throws(() => writeFileAtomic(path.join(dir, 'config.json'), 'hello'), /disk error/);
    assert.deepEqual(fs.readdirSync(dir), []);
  });
});
