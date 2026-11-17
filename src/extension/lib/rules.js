// Node と拡張機能の両方で使うため、Node 固有の API (Buffer など) は使わない
import { bytesToBase64 } from './vault-crypto.js';

// declarativeNetRequest の ResourceType をすべて列挙し、登録ホストへの全リクエストに付与する。
// 並び順は公式ドキュメントの enum に合わせる。
const RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
  'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket',
  'webtransport', 'webbundle', 'other',
];

function buildAuthorizationValue({ username, password }) {
  const credentials = new TextEncoder().encode(`${username}:${password}`);
  return `Basic ${bytesToBase64(credentials)}`;
}

// 既定では https / wss だけに送る。http (平文) は allowHttp で明示的に許可したエントリだけ。
// allowHttp を持たない以前の保存データは https のみとして扱う
const SECURE_SCHEMES = ['https', 'wss'];
const PLAINTEXT_SCHEMES = ['http', 'ws'];

function schemesOf({ allowHttp }) {
  return allowHttp === true ? [...SECURE_SCHEMES, ...PLAINTEXT_SCHEMES] : SECURE_SCHEMES;
}

// requestDomains でホストをドメイン (とサブドメイン) に限り、urlFilter でスキームを限る。
// 完全一致では urlFilter にホスト名まで含め、後ろを区切り文字 (^: ポートの ':' やパスの '/') に固定する。
// regexFilter は使わない (Chrome の正規表現のサイズ上限により、長いホスト名のルールが登録できないため)
function buildCondition({ domain, includeSubdomains }, scheme) {
  const urlFilter = includeSubdomains ? `|${scheme}://` : `|${scheme}://${domain}^`;
  return { requestDomains: [domain], urlFilter };
}

// 重なるルール (example.com のサブドメイン込みと api.example.com など) では、
// より限定的なルールを優先する: ラベル数が多いほど高く、同じなら完全一致を優先
function buildPriority({ domain, includeSubdomains }) {
  return domain.split('.').length * 2 + (includeSubdomains ? 0 : 1);
}

// urlFilter は 1 つのスキームしか表せないため、エントリのスキームごとにルールを作る (ID は後で振る)
function buildEntryRules(entry) {
  const priority = buildPriority(entry);
  const action = {
    type: 'modifyHeaders',
    requestHeaders: [
      { header: 'Authorization', operation: 'set', value: buildAuthorizationValue(entry) },
    ],
  };
  return schemesOf(entry).map((scheme) => ({
    priority,
    action,
    condition: { ...buildCondition(entry, scheme), resourceTypes: [...RESOURCE_TYPES] },
  }));
}

/**
 * エントリごとに Authorization ヘッダーを付与する declarativeNetRequest ルールを作る。
 * ルール ID は 1 から振る。
 */
export function buildRules(entries) {
  return entries.flatMap(buildEntryRules).map((rule, index) => ({ id: index + 1, ...rule }));
}
