// Node と拡張機能の両方で使うため、Node 固有の API (Buffer など) は使わない
import { bytesToBase64 } from './vault-crypto.js';

const RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'stylesheet',
  'image', 'font', 'media', 'websocket', 'other',
];

export function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildAuthorizationValue({ username, password }) {
  const credentials = new TextEncoder().encode(`${username}:${password}`);
  return `Basic ${bytesToBase64(credentials)}`;
}

// requestDomains はサブドメインにもマッチするため、完全一致が必要な場合は regexFilter を使う
function buildDomainCondition({ domain, includeSubdomains }) {
  if (includeSubdomains) return { requestDomains: [domain] };
  return { regexFilter: `^(?:https?|wss?)://${escapeRegExp(domain)}(?::\\d+)?/` };
}

// 重なるルール (example.com のサブドメイン込みと api.example.com など) では、
// より限定的なルールを優先する: ラベル数が多いほど高く、同じなら完全一致を優先
function buildPriority({ domain, includeSubdomains }) {
  return domain.split('.').length * 2 + (includeSubdomains ? 0 : 1);
}

function buildRule(entry, id) {
  return {
    id,
    priority: buildPriority(entry),
    action: {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'Authorization', operation: 'set', value: buildAuthorizationValue(entry) },
      ],
    },
    condition: {
      ...buildDomainCondition(entry),
      resourceTypes: [...RESOURCE_TYPES],
    },
  };
}

/**
 * エントリごとに Authorization ヘッダーを付与する declarativeNetRequest ルールを作る。
 * ルール ID は 1 から振る。
 */
export function buildRules(entries) {
  return entries.map((entry, index) => buildRule(entry, index + 1));
}
