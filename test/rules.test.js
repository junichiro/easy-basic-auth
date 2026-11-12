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

describe('buildRules', () => {
  test('includeSubdomains が false のときは regexFilter で完全一致させる', () => {
    const [rule] = buildRules([baseEntry]);
    assert.equal(rule.condition.requestDomains, undefined);
    assert.equal(rule.condition.regexFilter, '^(?:https?|wss?)://dashboard\\.example\\.com(?::\\d+)?/');
  });

  test('regexFilter は対象ドメインに一致し、サブドメインや似たドメインには一致しない', () => {
    const [rule] = buildRules([baseEntry]);
    const re = new RegExp(rule.condition.regexFilter);
    assert.ok(re.test('https://dashboard.example.com/'));
    assert.ok(re.test('http://dashboard.example.com:8080/path?q=1'));
    assert.ok(re.test('wss://dashboard.example.com/socket'));
    assert.ok(!re.test('https://sub.dashboard.example.com/'));
    assert.ok(!re.test('https://dashboardXexample.com/'));
    assert.ok(!re.test('https://dashboard.example.com.evil.test/'));
    assert.ok(!re.test('https://evil.test/?u=https://dashboard.example.com/'));
  });

  test('includeSubdomains が true のときは requestDomains を使う', () => {
    const [rule] = buildRules([{ ...baseEntry, includeSubdomains: true }]);
    assert.deepEqual(rule.condition.requestDomains, ['dashboard.example.com']);
    assert.equal(rule.condition.regexFilter, undefined);
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
    const [rule] = buildRules([baseEntry]);
    assert.deepEqual(rule.condition.resourceTypes, [
      'main_frame', 'sub_frame', 'xmlhttprequest', 'script', 'stylesheet',
      'image', 'font', 'media', 'websocket', 'other',
    ]);
  });

  test('ルール ID は 1 から振る', () => {
    const rules = buildRules([
      { ...baseEntry, domain: 'a.example.com' },
      { ...baseEntry, domain: 'b.example.com' },
    ]);
    assert.deepEqual(rules.map((r) => r.id), [1, 2]);
  });

  test('エントリが 0 件なら空配列を返す', () => {
    assert.deepEqual(buildRules([]), []);
  });
});
