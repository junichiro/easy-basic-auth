import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createAppServer } from '../src/server.js';

const TOKEN = 'test-token-123';
const MASTER = 'master password 1234';
const PASSWORD = 'super-secret-パスワード';

let server;
let port;
let configDir;

// Host ヘッダーを任意に指定したいので fetch ではなく node:http を使う
function request(method, urlPath, { headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      method,
      path: urlPath,
      headers: { host: `127.0.0.1:${port}`, ...headers },
    }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

function apiRequest(method, urlPath, { json, headers = {} } = {}) {
  const baseHeaders = { authorization: `Bearer ${TOKEN}` };
  if (method !== 'GET') baseHeaders.origin = `http://127.0.0.1:${port}`;
  if (json !== undefined) baseHeaders['content-type'] = 'application/json';
  return request(method, urlPath, {
    headers: { ...baseHeaders, ...headers },
    body: json === undefined ? undefined : JSON.stringify(json),
  });
}

before(async () => {
  configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eba-server-'));
  server = createAppServer({ configDir, token: TOKEN, kdfIterations: 1000 });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
});

after(() => new Promise((resolve) => server.close(resolve)));

describe('トークン検証', () => {
  test('トークンなしの API リクエストは 401 で拒否する', async () => {
    const res = await request('GET', '/api/status');
    assert.equal(res.status, 401);
  });

  test('不正なトークンは 401 で拒否する', async () => {
    const res = await request('GET', '/api/status', { headers: { authorization: 'Bearer wrong' } });
    assert.equal(res.status, 401);
  });
});

describe('Host ヘッダー検証', () => {
  test('不正な Host は 403 で拒否する', async () => {
    const res = await apiRequest('GET', '/api/status', { headers: { host: `evil.example.com:${port}` } });
    assert.equal(res.status, 403);
  });

  test('ポートが違う Host は拒否する', async () => {
    const res = await apiRequest('GET', '/api/status', { headers: { host: '127.0.0.1:1' } });
    assert.equal(res.status, 403);
  });

  test('静的ファイルも不正な Host なら拒否する', async () => {
    const res = await request('GET', '/', { headers: { host: 'evil.example.com' } });
    assert.equal(res.status, 403);
  });

  test('localhost:<port> は許可する', async () => {
    const res = await apiRequest('GET', '/api/status', { headers: { host: `localhost:${port}` } });
    assert.equal(res.status, 200);
  });
});

describe('Origin 検証', () => {
  test('不正な Origin の POST は 403 で拒否する', async () => {
    const res = await apiRequest('POST', '/api/setup', {
      json: { masterPassword: MASTER }, headers: { origin: 'https://evil.example.com' },
    });
    assert.equal(res.status, 403);
  });

  test('Origin なしの POST は 403 で拒否する', async () => {
    const res = await request('POST', '/api/setup', {
      headers: { authorization: `Bearer ${TOKEN}`, 'content-type': 'application/json' },
      body: JSON.stringify({ masterPassword: MASTER }),
    });
    assert.equal(res.status, 403);
  });
});

describe('CORS', () => {
  test('CORS ヘッダーを付けない', async () => {
    const res = await apiRequest('GET', '/api/status', { headers: { origin: 'https://evil.example.com' } });
    assert.equal(res.headers['access-control-allow-origin'], undefined);
  });
});

// 以下はテストの実行順に依存するシナリオ
describe('初期設定からエントリ操作までの流れ', () => {
  let createdId;

  test('最初は未初期化', async () => {
    const res = await apiRequest('GET', '/api/status');
    assert.deepEqual(JSON.parse(res.body), { initialized: false, unlocked: false, needsMigration: false, minMasterPasswordLength: 12 });
  });

  test('初期化前のエントリ操作は 423 を返す', async () => {
    const res = await apiRequest('GET', '/api/state');
    assert.equal(res.status, 423);
  });

  test('短いマスターパスワードでは初期設定できない', async () => {
    const res = await apiRequest('POST', '/api/setup', { json: { masterPassword: 'short' } });
    assert.equal(res.status, 400);
  });

  test('マスターパスワードを設定するとアンロックされる', async () => {
    const res = await apiRequest('POST', '/api/setup', { json: { masterPassword: MASTER } });
    assert.equal(res.status, 200);
    assert.ok(!res.body.includes(MASTER));
    const status = JSON.parse((await apiRequest('GET', '/api/status')).body);
    assert.equal(status.unlocked, true);
  });

  test('2 回目の初期設定は 409 を返す', async () => {
    const res = await apiRequest('POST', '/api/setup', { json: { masterPassword: MASTER } });
    assert.equal(res.status, 409);
  });

  test('エントリを追加できる', async () => {
    const res = await apiRequest('POST', '/api/entries', {
      json: { label: 'L', domain: 'https://Secure.Example.com/', username: 'user', password: PASSWORD },
    });
    assert.equal(res.status, 201);
    const state = JSON.parse(res.body);
    createdId = state.entries[0].id;
    assert.equal(state.entries[0].domain, 'secure.example.com');
    assert.equal(state.extensionDir, path.join(configDir, 'extension'));
  });

  test('パスワードがレスポンスに含まれない', async () => {
    const res = await apiRequest('GET', '/api/state');
    assert.ok(!res.body.includes(PASSWORD));
    const [entry] = JSON.parse(res.body).entries;
    assert.equal(entry.password, undefined);
    assert.equal(entry.hasPassword, true);
  });

  test('パスワード欄を空で更新しても既存のパスワードを維持する', async () => {
    const res = await apiRequest('PUT', `/api/entries/${createdId}`, { json: { username: 'user2', password: '' } });
    assert.equal(res.status, 200);
    assert.equal(JSON.parse(res.body).entries[0].hasPassword, true);
  });

  test('不正な入力は 400 とエラーメッセージを返す', async () => {
    const res = await apiRequest('POST', '/api/entries', { json: { domain: '', username: 'u', password: 'p' } });
    assert.equal(res.status, 400);
    assert.ok(JSON.parse(res.body).error);
  });

  test('存在しない ID は 404 を返す', async () => {
    const res = await apiRequest('DELETE', '/api/entries/no-such-id');
    assert.equal(res.status, 404);
  });

  test('不正なパーセントエンコードの ID は 404 を返す', async () => {
    const res = await apiRequest('DELETE', '/api/entries/%E0');
    assert.equal(res.status, 404);
  });

  test('GET で状態を変える操作はできない', async () => {
    const res = await apiRequest('GET', '/api/generate');
    assert.equal(res.status, 405);
  });

  test('ロックするとエントリ操作は 423 とロック中である旨を返す', async () => {
    assert.equal((await apiRequest('POST', '/api/lock')).status, 200);
    const res = await apiRequest('GET', '/api/state');
    assert.equal(res.status, 423);
    assert.match(JSON.parse(res.body).error, /ロックされています/);
  });

  test('誤ったマスターパスワードではアンロックできない', async () => {
    const res = await apiRequest('POST', '/api/unlock', { json: { masterPassword: 'wrong password!!' } });
    assert.equal(res.status, 400);
  });

  test('正しいマスターパスワードでアンロックできる', async () => {
    const res = await apiRequest('POST', '/api/unlock', { json: { masterPassword: MASTER } });
    assert.equal(res.status, 200);
    assert.equal((await apiRequest('GET', '/api/state')).status, 200);
  });

  test('マスターパスワードを変更できる', async () => {
    const next = 'next master password 5678';
    const res = await apiRequest('POST', '/api/master-password', {
      json: { currentPassword: MASTER, newPassword: next },
    });
    assert.equal(res.status, 200);
    await apiRequest('POST', '/api/lock');
    assert.equal((await apiRequest('POST', '/api/unlock', { json: { masterPassword: next } })).status, 200);
  });

  test('エントリを削除できる', async () => {
    const res = await apiRequest('DELETE', `/api/entries/${createdId}`);
    assert.equal(res.status, 200);
    assert.deepEqual(JSON.parse(res.body).entries, []);
  });
});

describe('静的ファイル', () => {
  test('トークンなしで index.html を返す', async () => {
    const res = await request('GET', '/?token=abc');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /text\/html/);
    assert.equal(res.headers['referrer-policy'], 'no-referrer');
  });

  test('public 外のファイルは返さない', async () => {
    const res = await request('GET', '/../package.json');
    assert.equal(res.status, 404);
    const encoded = await request('GET', '/%2e%2e/package.json');
    assert.equal(encoded.status, 404);
  });
});
