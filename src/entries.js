import crypto from 'node:crypto';

export class ValidationError extends Error {
  constructor(message, field) {
    super(message);
    this.name = 'ValidationError';
    this.field = field;
  }
}

const EDITABLE_FIELDS = ['label', 'domain', 'includeSubdomains', 'username', 'password', 'enabled'];
const HOSTNAME_PATTERN = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;
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

function normalizeLabel(input, domain) {
  const label = asString(input).trim();
  if (label.length > MAX_LABEL_LENGTH) {
    throw new ValidationError(`ラベルは ${MAX_LABEL_LENGTH} 文字以内にしてください`, 'label');
  }
  return label || domain;
}

function normalizeEntryFields(fields) {
  const domain = normalizeDomain(fields.domain);
  return {
    label: normalizeLabel(fields.label, domain),
    domain,
    includeSubdomains: fields.includeSubdomains === true,
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
  return { id: existing.id, ...normalizeEntryFields({ ...existing, ...changes }) };
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
