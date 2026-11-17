import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { resolveConfigDir } from './config.js';
import { ValidationError } from './entries.js';
import { createEntryService, NotFoundError } from './service.js';
import { StateError } from './errors.js';
import { createSession, LockedError } from './session.js';

const DEFAULT_PORT = 4729;
const BIND_HOST = '127.0.0.1';
const MAX_BODY_BYTES = 64 * 1024;
const PUBLIC_DIR = fileURLToPath(new URL('./public/', import.meta.url));

// 配信するファイルはホワイトリストで限定する（パストラバーサル対策）
const STATIC_FILES = {
  '/': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/index.html': { file: 'index.html', type: 'text/html; charset=utf-8' },
  '/app.js': { file: 'app.js', type: 'text/javascript; charset=utf-8' },
  '/style.css': { file: 'style.css', type: 'text/css; charset=utf-8' },
};

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'DELETE']);

class HttpError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.name = 'HttpError';
    this.statusCode = statusCode;
  }
}

const ROUTES = [
  { method: 'GET', pattern: /^\/api\/status$/, handle: ({ service }) => [200, service.getStatus()] },
  { method: 'POST', pattern: /^\/api\/setup$/, handle: ({ service, body }) => [200, service.setup(body.masterPassword)] },
  { method: 'POST', pattern: /^\/api\/unlock$/, handle: ({ service, body }) => [200, service.unlock(body.masterPassword)] },
  { method: 'POST', pattern: /^\/api\/lock$/, handle: ({ service }) => [200, service.lock()] },
  {
    method: 'POST',
    pattern: /^\/api\/master-password$/,
    handle: ({ service, body }) => [200, service.changeMasterPassword(body.currentPassword, body.newPassword)],
  },
  { method: 'GET', pattern: /^\/api\/state$/, handle: ({ service }) => [200, service.getState()] },
  { method: 'POST', pattern: /^\/api\/entries$/, handle: ({ service, body }) => [201, service.addEntry(body)] },
  { method: 'PUT', pattern: /^\/api\/entries\/([^/]+)$/, handle: ({ service, body, params }) => [200, service.updateEntry(params[0], body)] },
  { method: 'DELETE', pattern: /^\/api\/entries\/([^/]+)$/, handle: ({ service, params }) => [200, service.deleteEntry(params[0])] },
  { method: 'POST', pattern: /^\/api\/generate$/, handle: ({ service }) => [200, service.regenerate()] },
];

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest();
}

// 長さの違いでタイミングが漏れないよう、ハッシュ同士を比較する
function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha256(a), sha256(b));
}

function allowedAuthorities(port) {
  return [`127.0.0.1:${port}`, `localhost:${port}`];
}

function isAllowedHost(req) {
  return allowedAuthorities(req.socket.localPort).includes(req.headers.host ?? '');
}

function isAllowedOrigin(req) {
  const origins = allowedAuthorities(req.socket.localPort).map((authority) => `http://${authority}`);
  return origins.includes(req.headers.origin ?? '');
}

function hasValidToken(req, token) {
  const match = /^Bearer (.+)$/.exec(req.headers.authorization ?? '');
  return Boolean(match) && safeEqual(match[1], token);
}

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(payload));
}

function decodeRouteParam(param) {
  try {
    return decodeURIComponent(param);
  } catch {
    // 不正なパーセントエンコードは存在しない ID として扱う
    throw new HttpError(404, 'Not found');
  }
}

function matchRoute(method, pathname) {
  const candidates = ROUTES
    .map((route) => ({ route, match: route.pattern.exec(pathname) }))
    .filter(({ match }) => match);
  if (candidates.length === 0) throw new HttpError(404, 'Not found');

  const found = candidates.find(({ route }) => route.method === method);
  if (!found) throw new HttpError(405, 'Method not allowed');
  return { handle: found.route.handle, params: found.match.slice(1).map(decodeRouteParam) };
}

async function readJsonBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Request body too large');
    chunks.push(chunk);
  }
  if (size === 0) return {};

  if (!/^application\/json\b/.test(req.headers['content-type'] ?? '')) {
    throw new HttpError(415, 'Content-Type must be application/json');
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
}

function assertApiAccess(req, token) {
  if (!hasValidToken(req, token)) throw new HttpError(401, 'Invalid or missing token');
  if (STATE_CHANGING_METHODS.has(req.method) && !isAllowedOrigin(req)) {
    throw new HttpError(403, 'Invalid origin');
  }
}

function toErrorResponse(error) {
  if (error instanceof HttpError) return [error.statusCode, { error: error.message }];
  if (error instanceof ValidationError) return [400, { error: error.message, field: error.field }];
  if (error instanceof NotFoundError) return [404, { error: 'エントリが見つかりません' }];
  if (error instanceof LockedError) return [423, { error: error.message, locked: true }];
  if (error instanceof StateError) return [409, { error: error.message }];

  console.error('[edge-basic-auth] Unexpected error:', error);
  return [500, { error: '内部エラーが発生しました。サーバーのログを確認してください' }];
}

async function handleApi(req, res, pathname, { service, token }) {
  try {
    assertApiAccess(req, token);
    const { handle, params } = matchRoute(req.method, pathname);
    const body = STATE_CHANGING_METHODS.has(req.method) ? await readJsonBody(req) : undefined;
    const [statusCode, payload] = handle({ service, body: body ?? {}, params });
    sendJson(res, statusCode, await payload);
  } catch (error) {
    sendJson(res, ...toErrorResponse(error));
  }
}

function handleStatic(req, res, pathname, publicDir) {
  const asset = STATIC_FILES[pathname];
  if (req.method !== 'GET' || !asset) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }
  // 読み込みに失敗したときに 500 を返せるよう、ヘッダー送信より前に読む
  const content = fs.readFileSync(path.join(publicDir, asset.file));
  res.writeHead(200, { 'Content-Type': asset.type });
  res.end(content);
}

function parsePathname(url) {
  try {
    return new URL(url, 'http://localhost').pathname;
  } catch {
    throw new HttpError(400, 'Invalid request URL');
  }
}

async function routeRequest(req, res, { service, token, publicDir }) {
  // DNS リバインディング対策: Host が自分自身でなければ一切応答しない
  if (!isAllowedHost(req)) {
    sendJson(res, 403, { error: 'Invalid host' });
    return;
  }

  const pathname = parsePathname(req.url);
  if (pathname.startsWith('/api/')) {
    await handleApi(req, res, pathname, { service, token });
    return;
  }
  handleStatic(req, res, pathname, publicDir);
}

// http サーバーはハンドラーの Promise を無視するため、ここで全ての例外を受け止めてプロセスの終了を防ぐ
function respondToUnhandledError(res, error) {
  if (res.headersSent) {
    console.error('[edge-basic-auth] Error after response headers were sent:', error);
    res.end();
    return;
  }
  sendJson(res, ...toErrorResponse(error));
}

export function createRequestHandler({ service, token, publicDir = PUBLIC_DIR }) {
  return async (req, res) => {
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.setHeader(name, value);
    try {
      await routeRequest(req, res, { service, token, publicDir });
    } catch (error) {
      respondToUnhandledError(res, error);
    }
  };
}

export function createAppServer({ configDir, token, publicDir, kdfIterations, idleTimeoutMs }) {
  const session = createSession({ idleTimeoutMs });
  const service = createEntryService({ configDir, session, kdfIterations });
  return http.createServer(createRequestHandler({ service, token, publicDir }));
}

function parsePort(value) {
  if (value === undefined || value === '') return DEFAULT_PORT;
  const port = Number(value);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid PORT: ${value}`);
  }
  return port;
}

/**
 * サーバーを起動できなかったときの案内。ポートを使っているのは、たいてい起動済みのこのツール自身。
 * 同じ CONFIG_DIR に 2 つのサーバーを立てると保存が失われるため、別のポートでの起動は勧めない
 */
export function describeListenError(error, port) {
  if (error?.code !== 'EADDRINUSE') return `[edge-basic-auth] Server error: ${error?.message ?? error}`;
  return [
    `ポート ${port} は使用中です。`,
    'このツールがすでに起動している場合は、そのコンソールに表示された URL を開いてください（同じ設定フォルダに対して 2 つ起動しないでください）。',
    '別のプログラムがこのポートを使っている場合は、環境変数 PORT に別のポート番号を指定して起動してください。',
  ].join('\n');
}

function main() {
  const port = parsePort(process.env.PORT);
  const configDir = resolveConfigDir();
  const token = crypto.randomBytes(32).toString('base64url');
  const server = createAppServer({ configDir, token });

  server.on('error', (error) => {
    console.error(describeListenError(error, port));
    process.exitCode = 1;
  });

  server.listen(port, BIND_HOST, () => {
    const actualPort = server.address().port;
    console.log('edge-basic-auth 設定 UI を起動しました。ブラウザで以下を開いてください:');
    console.log(`  http://${BIND_HOST}:${actualPort}/?token=${token}`);
    console.log(`設定ディレクトリ: ${configDir}`);
    console.log('終了するには Ctrl+C を押してください。');
  });
}

const isEntryPoint = process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href;
if (isEntryPoint) main();
