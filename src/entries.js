import crypto from 'node:crypto';
import { isPublicSuffix } from './public-suffix.js';

export class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

const EDITABLE_FIELDS = ['label', 'domain', 'includeSubdomains', 'allowHttp', 'username', 'password', 'enabled'];
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
const PLAINTEXT_SCHEME = /^(?:http|ws):\/\//i;
const MAX_LABEL_LENGTH = 100;

function asString(value) {
  return typeof value === 'string' ? value : '';
}

function parseAsUrl(text) {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`;
  try {
    return new URL(withScheme);
  } catch {
    return null;
  }
}

/**
 * 入力をホスト名のみ (小文字) に正規化する。スキーム・ポート・パスは除去する。
 */
export function normalizeDomain(input) {
  const text = asString(input).trim();
  if (!text) throw new ValidationError('ドメインを入力してください', 'domain');

  const url = parseAsUrl(text);
  if (!url) throw new ValidationError(`ドメインの形式が正しくありません: ${text}`, 'domain');
  if (url.username || url.password) {
    throw new ValidationError('ドメインにユーザー名やパスワードを含めないでください', 'domain');
  }

  const hostname = url.hostname.toLowerCase();
  if (!HOSTNAME_PATTERN.test(hostname)) {
    throw new ValidationError(`ドメインの形式が正しくありません: ${text}`, 'domain');
  }
  return hostname;
}

function normalizeUsername(input) {
  const username = asString(input);
  if (!username) throw new ValidationError('ユーザー名を入力してください', 'username');
  if (username.includes(':')) throw new ValidationError('ユーザー名にコロン (:) は使えません', 'username');
  if (CONTROL_CHARS.test(username)) throw new ValidationError('ユーザー名に制御文字は使えません', 'username');
  return username;
}

function normalizePassword(input) {
  const password = asString(input);
  if (!password) throw new ValidationError('パスワードを入力してください', 'password');
  return password;
}

// ラベルを省略するとドメインをラベルにする。ドメインは 100 文字を超えうるため、
// ドメインと同じラベル (既定のラベル) には文字数の上限を適用しない
function normalizeLabel(input, domain) {
  const label = asString(input).trim();
  if (label.length > MAX_LABEL_LENGTH && label !== domain) {
    throw new ValidationError(`ラベルは ${MAX_LABEL_LENGTH} 文字以内にしてください`, 'label');
  }
  return label || domain;
}

// http の URL が貼り付けられたのに http を許可していなければ、黙って https 用に登録せず案内する
function assertSchemeAllowed(domainInput, allowHttp) {
  if (allowHttp || !PLAINTEXT_SCHEME.test(asString(domainInput).trim())) return;
  throw new ValidationError(
    'http（平文）の URL です。既定では https にだけ認証情報を送ります。'
    + 'http で送る必要がある場合は「http（平文）を許可」を ON にしてください',
    'domain',
  );
}

// 公開サフィックスの配下すべて (他者のサイト) に認証情報が送られるのを防ぐ
function normalizeIncludeSubdomains(input, domain) {
  if (input !== true) return false;
  if (!isPublicSuffix(domain)) return true;
  throw new ValidationError(
    `${domain} は多くの組織や利用者が共有するドメインのため、「サブドメインを含む」は使えません。`
    + `「サブドメインを含む」を OFF にするか、自分のサイトのドメイン (例: myapp.${domain}) を登録してください`,
    'includeSubdomains',
  );
}

function normalizeEntryFields(fields) {
  // allowHttp を持たない以前の保存データは https のみとして扱う
  const allowHttp = fields.allowHttp === true;
  assertSchemeAllowed(fields.domain, allowHttp);
  const domain = normalizeDomain(fields.domain);
  return {
    label: normalizeLabel(fields.label, domain),
    domain,
    includeSubdomains: normalizeIncludeSubdomains(fields.includeSubdomains, domain),
    allowHttp,
    username: normalizeUsername(fields.username),
    password: normalizePassword(fields.password),
    enabled: fields.enabled === true,
  };
}

function pickEditableFields(input) {
  const source = input && typeof input === 'object' ? input : {};
  return Object.fromEntries(
    EDITABLE_FIELDS.filter((key) => source[key] !== undefined).map((key) => [key, source[key]]),
  );
}

export function createEntry(input, generateId = crypto.randomUUID) {
  const fields = { enabled: true, ...pickEditableFields(input) };
  return { id: generateId(), ...normalizeEntryFields(fields) };
}

/**
 * 指定されたフィールドだけを更新する。パスワードが空なら既存の値を維持する。
 */
export function updateEntry(existing, input) {
  const changes = pickEditableFields(input);
  if (!changes.password) delete changes.password;
  const updated = normalizeEntryFields({ ...existing, ...changes });
  if (followsDefaultLabel(existing, changes, updated)) updated.label = updated.domain;
  return { id: existing.id, ...updated };
}

/**
 * 既定のラベル (ラベル = ドメイン) のままドメインだけが変わった場合、ラベルも新しいドメインに追従させるかを判定する。
 * ユーザーが別のラベルを明示的に送ってきた場合は追従させない。
 */
function followsDefaultLabel(existing, changes, updated) {
  if (existing.label !== existing.domain) return false;
  if (updated.domain === existing.domain) return false;
  const submittedLabel = asString(changes.label ?? existing.label).trim();
  return submittedLabel === '' || submittedLabel === existing.domain;
}

export function assertUniqueDomain(entries, candidate) {
  const duplicate = entries.find((entry) => entry.id !== candidate.id && entry.domain === candidate.domain);
  if (duplicate) {
    throw new ValidationError(`${candidate.domain} は既に登録されています（${duplicate.label}）`, 'domain');
  }
}

/**
 * UI に返すための表現。パスワードは絶対に含めない。
 */
export function toPublicEntry({ password, ...rest }) {
  return { ...rest, hasPassword: Boolean(password) };
}
