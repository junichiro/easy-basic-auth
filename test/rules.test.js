import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { buildRules, escapeRegExp } from '../src/extension/lib/rules.js';

const baseEntry = {
  domain: 'dashboard.example.com',
  includeSubdomains: false,
  username: 'user',
  password: 'pass',
};

describe('escapeRegExp', () => {
  test('ドットなど正規表現の特殊文字をエスケープする', () => {
    assert.equal(escapeRegExp('a.b-c'), 'a\\.b-c');
    assert.equal(escapeRegExp('x*+?^$()[]{}|\\'), 'x\\*\\+\\?\\^\\$\\(\\)\\[\\]\\{\\}\\|\\\\');
  });
});

// Chrome の requestDomains と urlFilter の一致を、テスト用に簡略化して再現する。
// urlFilter: 先頭の '|' は URL の先頭に固定、'^' は区切り文字 (英数字と _ - . % 以外) か URL の末尾
function urlFilterToRegExp(filter) {
  const body = filter.replace(/^\|/, '').split('^').map(escapeRegExp).join('(?:[^A-Za-z0-9_.%-]|$)');
  return new RegExp(`^${body}`, 'i');
}

function ruleMatches(rule, url) {
  const { hostname } = new URL(url);
  const { requestDomains, urlFilter } = rule.condition;
  const inDomains = requestDomains.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`));
  return inDomains && urlFilterToRegExp(urlFilter).test(url);
}

function matchingRules(rules, url) {
  return rules.filter((rule) => ruleMatches(rule, url));
}

function sendsTo(entry, url) {
  return matchingRules(buildRules([entry]), url).length > 0;
}

describe('buildRules', () => {
  test('完全一致のエントリは、対象ドメインの https・wss に一致する', () => {
    for (const url of [
      'https://dashboard.example.com/',
      'https://dashboard.example.com:8443/path?q=1',
      'https://dashboard.example.com',
      'wss://dashboard.example.com/socket',
    ]) assert.ok(sendsTo(baseEntry, url), url);
  });

  test('完全一致のエントリは、サブドメインや似たドメインには一致しない', () => {
    for (const url of [
      'https://sub.dashboard.example.com/',
      'https://dashboardXexample.com/',
      'https://dashboard.example.com.evil.test/',
      'https://evil.test/?u=https://dashboard.example.com/',
      'https://dashboard.example.com@evil.test/',
      'https://dashboard.example.co/',
    ]) assert.ok(!sendsTo(baseEntry, url), url);
  });

  test('サブドメインを含むエントリは、ドメイン自身とサブドメインの https・wss に一致する', () => {
    const entry = { ...baseEntry, includeSubdomains: true };
    for (const url of [
      'https://dashboard.example.com/',
      'https://a.b.dashboard.example.com:8443/x',
      'wss://sub.dashboard.example.com/socket',
    ]) assert.ok(sendsTo(entry, url), url);
    assert.ok(!sendsTo(entry, 'https://xdashboard.example.com/'));
  });

  test('正規表現 (regexFilter) を使わない: 長いホスト名でも Chrome の正規表現のサイズ上限や件数の上限に当たらない', () => {
    const longDomain = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(57)}.example`;
    const rules = buildRules([
      { ...baseEntry, domain: longDomain },
      { ...baseEntry, includeSubdomains: true, allowHttp: true },
    ]);
    for (const rule of rules) assert.equal(rule.condition.regexFilter, undefined);
    assert.ok(sendsTo({ ...baseEntry, domain: longDomain }, `https://${longDomain}/`));
  });

  test('Authorization ヘッダーを Basic 認証の値で set する', () => {
    const [rule] = buildRules([baseEntry]);
    assert.deepEqual(rule.action, {
      type: 'modifyHeaders',
      requestHeaders: [
        { header: 'Authorization', operation: 'set', value: 'Basic dXNlcjpwYXNz' },
      ],
    });
  });

  test('非 ASCII を含むパスワードを UTF-8 で base64 化する', () => {
    const [rule] = buildRules([{ ...baseEntry, username: 'ユーザー', password: 'パス🔑' }]);
    const value = rule.action.requestHeaders[0].value;
    assert.equal(value, 'Basic 44Om44O844K244O8OuODkeOCufCflJE=');
  });

  test('対象のリソースタイプを指定する', () => {
    for (const rule of buildRules([baseEntry])) {
      assert.deepEqual(rule.condition.resourceTypes, [
        'main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font',
        'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket',
        'webtransport', 'webbundle', 'other',
      ]);
    }
  });

  test('ルール ID は 1 から重複なく連番で振る', () => {
    const rules = buildRules([
      { ...baseEntry, domain: 'a.example.com' },
      { ...baseEntry, domain: 'b.example.com', allowHttp: true },
    ]);
    assert.deepEqual(rules.map((r) => r.id), rules.map((_, index) => index + 1));
  });

  test('重なるルールでは、より限定的なルールを高い優先度にする', () => {
    const rules = buildRules([
      { ...baseEntry, domain: 'example.com', includeSubdomains: true, username: 'wildcard' },
      { ...baseEntry, domain: 'api.example.com', includeSubdomains: false, username: 'exact' },
      { ...baseEntry, domain: 'dev.example.com', includeSubdomains: true, username: 'deeper' },
    ]);
    const winner = (url) => {
      const [top] = matchingRules(rules, url).sort((a, b) => b.priority - a.priority);
      return atob(top.action.requestHeaders[0].value.replace('Basic ', '')).split(':')[0];
    };
    assert.equal(winner('https://api.example.com/'), 'exact', '完全一致 > サブドメイン込み');
    assert.equal(winner('https://x.dev.example.com/'), 'deeper', '長いドメイン > 短いドメイン');
    assert.equal(winner('https://www.example.com/'), 'wildcard');
  });

  test('エントリが 0 件なら空配列を返す', () => {
    assert.deepEqual(buildRules([]), []);
  });

  describe('http (平文) の扱い', () => {
    const plainUrls = [
      'http://dashboard.example.com/',
      'http://dashboard.example.com:8080/path?q=1',
      'ws://dashboard.example.com/socket',
    ];

    test('allowHttp がなければ、完全一致のエントリは http・ws に一致しない', () => {
      for (const url of plainUrls) assert.ok(!sendsTo(baseEntry, url), url);
    });

    test('allowHttp がなければ、サブドメイン込みのエントリも http・ws に一致しない', () => {
      const entry = { ...baseEntry, includeSubdomains: true };
      for (const url of [...plainUrls, 'http://sub.dashboard.example.com/']) assert.ok(!sendsTo(entry, url), url);
    });

    test('allowHttp が true なら、完全一致のエントリは http・ws にも一致する', () => {
      const entry = { ...baseEntry, allowHttp: true };
      for (const url of [...plainUrls, 'https://dashboard.example.com/']) assert.ok(sendsTo(entry, url), url);
      assert.ok(!sendsTo(entry, 'http://sub.dashboard.example.com/'));
    });

    test('allowHttp が true なら、サブドメイン込みのエントリも http・ws に一致する', () => {
      const entry = { ...baseEntry, includeSubdomains: true, allowHttp: true };
      for (const url of [...plainUrls, 'http://sub.dashboard.example.com/']) assert.ok(sendsTo(entry, url), url);
    });

    test('allowHttp が true 以外 (文字列など) なら http を許可しない', () => {
      assert.ok(!sendsTo({ ...baseEntry, allowHttp: 'true' }, 'http://dashboard.example.com/'));
    });
  });
});
