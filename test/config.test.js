import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  resolveConfigDir,
  readConfig,
  writeConfig,
} from '../src/config.js';

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'eba-config-'));
}

describe('resolveConfigDir', () => {
  test('EDGE_BASIC_AUTH_DIR が設定されていれば最優先で使う', () => {
    const dir = resolveConfigDir({
      env: { EDGE_BASIC_AUTH_DIR: '/custom/dir', XDG_CONFIG_HOME: '/xdg' },
      platform: 'darwin',
      homedir: '/home/u',
    });
    assert.equal(dir, path.resolve('/custom/dir'));
  });

  test('macOS / Linux では XDG_CONFIG_HOME 配下を使う', () => {
    const dir = resolveConfigDir({ env: { XDG_CONFIG_HOME: '/xdg' }, platform: 'linux', homedir: '/home/u' });
    assert.equal(dir, path.join('/xdg', 'edge-basic-auth'));
  });

  test('XDG_CONFIG_HOME が未設定なら ~/.config 配下を使う', () => {
    const dir = resolveConfigDir({ env: {}, platform: 'darwin', homedir: '/Users/u' });
    assert.equal(dir, path.join('/Users/u', '.config', 'edge-basic-auth'));
  });

  test('Windows では APPDATA 配下を使う', () => {
    const dir = resolveConfigDir({
      env: { APPDATA: 'C:\\Users\\u\\AppData\\Roaming' },
      platform: 'win32',
      homedir: 'C:\\Users\\u',
    });
    assert.equal(dir, path.join('C:\\Users\\u\\AppData\\Roaming', 'edge-basic-auth'));
  });
});

describe('readConfig / writeConfig', () => {
  test('config.json が無ければ null を返す', () => {
    assert.equal(readConfig(makeTempDir()), null);
  });

  test('書き込んだ設定を読み戻せる', () => {
    const dir = path.join(makeTempDir(), 'nested');
    const config = { version: 2, extensionVersionCounter: 3, vault: { iv: 'a', ciphertext: 'b' } };
    writeConfig(dir, config);
    assert.deepEqual(readConfig(dir), config);
  });

  test('壊れた JSON は原因がわかるエラーにする', () => {
    const dir = makeTempDir();
    fs.writeFileSync(path.join(dir, 'config.json'), '{ broken');
    assert.throws(() => readConfig(dir), /config\.json/);
  });

  test('一時ファイルを残さない', () => {
    const dir = makeTempDir();
    writeConfig(dir, { version: 2 });
    assert.deepEqual(fs.readdirSync(dir), ['config.json']);
  });

  test('POSIX 環境ではディレクトリを 0700、ファイルを 0600 にする', { skip: process.platform === 'win32' }, () => {
    const dir = path.join(makeTempDir(), 'conf');
    fs.mkdirSync(dir, { mode: 0o755 });
    writeConfig(dir, { version: 2 });
    assert.equal(fs.statSync(dir).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(dir, 'config.json')).mode & 0o777, 0o600);
  });
});
