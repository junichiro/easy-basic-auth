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

function buildRule(entry, id) {
  return {
    id,
    priority: 1,
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
