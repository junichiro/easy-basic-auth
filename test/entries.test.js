import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeDomain,
  createEntry,
  updateEntry,
  toPublicEntry,
  ValidationError,
} from '../src/entries.js';

const fixedId = () => 'fixed-id';

describe('normalizeDomain', () => {
  test('小文字に正規化する', () => {
    assert.equal(normalizeDomain('Dashboard.Example.COM'), 'dashboard.example.com');
  });

  test('スキーム・ポート・パスを除去する', () => {
    assert.equal(normalizeDomain('https://dashboard.example.com:8443/path?q=1'), 'dashboard.example.com');
    assert.equal(normalizeDomain('dashboard.example.com/foo'), 'dashboard.example.com');
    assert.equal(normalizeDomain('  dashboard.example.com  '), 'dashboard.example.com');
  });

  test('ユーザー情報付きの URL は拒否する', () => {
    assert.throws(() => normalizeDomain('https://u:p@dashboard.example.com/'), ValidationError);
  });

  test('空やホスト名として不正な値は拒否する', () => {
    for (const input of ['', '   ', '*.example.com', 'exa mple.com', '[::1]', '.example.com']) {
      assert.throws(() => normalizeDomain(input), ValidationError, input);
    }
  });
});

describe('createEntry', () => {
  const input = {
    label: ' 社内 ',
    domain: 'Dashboard.Example.com',
    username: 'user',
    password: 'pass',
  };

  test('入力を正規化して新しいエントリを作る', () => {
    assert.deepEqual(createEntry(input, fixedId), {
      id: 'fixed-id',
      label: '社内',
      domain: 'dashboard.example.com',
      includeSubdomains: false,
      allowHttp: false,
      username: 'user',
      password: 'pass',
      enabled: true,
    });
  });

  test('ラベルが空ならドメインをラベルにする', () => {
    assert.equal(createEntry({ ...input, label: '' }, fixedId).label, 'dashboard.example.com');
  });

  test('includeSubdomains は true のときだけ有効になる', () => {
    assert.equal(createEntry({ ...input, includeSubdomains: true }, fixedId).includeSubdomains, true);
    assert.equal(createEntry({ ...input, includeSubdomains: 'true' }, fixedId).includeSubdomains, false);
  });

  test('allowHttp は true のときだけ有効になり、既定は false (https のみ)', () => {
    assert.equal(createEntry({ ...input, allowHttp: true }, fixedId).allowHttp, true);
    assert.equal(createEntry({ ...input, allowHttp: 'true' }, fixedId).allowHttp, false);
    assert.equal(createEntry(input, fixedId).allowHttp, false);
  });

  test('http:// の URL を貼り付けても allowHttp がなければ拒否し、許可の方法を案内する', () => {
    assert.throws(() => createEntry({ ...input, domain: 'http://dashboard.example.com/' }, fixedId), (error) => {
      assert.ok(error instanceof ValidationError);
      assert.equal(error.field, 'domain');
      assert.match(error.message, /http（平文）を許可/);
      return true;
    });
  });

  test('http:// の URL でも allowHttp が true なら登録できる', () => {
    const entry = createEntry({ ...input, domain: 'http://dashboard.example.com/', allowHttp: true }, fixedId);
    assert.equal(entry.domain, 'dashboard.example.com');
    assert.equal(entry.allowHttp, true);
  });

  test('パスワードが空なら拒否する', () => {
    assert.throws(() => createEntry({ ...input, password: '' }, fixedId), ValidationError);
  });

  test('ユーザー名が空、またはコロンを含む場合は拒否する', () => {
    assert.throws(() => createEntry({ ...input, username: '' }, fixedId), ValidationError);
    assert.throws(() => createEntry({ ...input, username: 'a:b' }, fixedId), ValidationError);
  });
});

describe('updateEntry', () => {
  const existing = {
    id: 'id-1',
    label: '旧',
    domain: 'old.example.com',
    includeSubdomains: false,
    allowHttp: false,
    username: 'old',
    password: 'secret',
    enabled: true,
  };

  test('パスワードが空なら既存の値を維持する', () => {
    const updated = updateEntry(existing, { password: '', username: 'new' });
    assert.equal(updated.password, 'secret');
    assert.equal(updated.username, 'new');
  });

  test('パスワードを指定すれば更新する', () => {
    assert.equal(updateEntry(existing, { password: 'next' }).password, 'next');
  });

  test('指定されたフィールドだけ更新し、ID は変えない', () => {
    const updated = updateEntry(existing, { enabled: false, id: 'hacked' });
    assert.deepEqual(updated, { ...existing, enabled: false });
  });

  test('allowHttp を持たない既存のエントリ (以前の保存データ) は https のみとして扱う', () => {
    const { allowHttp, ...legacy } = existing;
    assert.equal(updateEntry(legacy, { username: 'new' }).allowHttp, false);
  });

  test('allowHttp を更新できる', () => {
    assert.equal(updateEntry(existing, { allowHttp: true }).allowHttp, true);
  });

  test('ドメインを更新するときも正規化する', () => {
    assert.equal(updateEntry(existing, { domain: 'HTTPS://New.Example.com/' }).domain, 'new.example.com');
  });

  describe('既定のラベル (ラベル = ドメイン) の追従', () => {
    const defaultLabeled = { ...existing, label: 'old.example.com' };

    test('旧ドメインと同じラベルのままドメインを変えると、ラベルは新しいドメインになる', () => {
      const updated = updateEntry(defaultLabeled, { label: 'old.example.com', domain: 'new.example.com' });
      assert.equal(updated.label, 'new.example.com');
    });

    test('ラベルを省略してドメインを変えると、ラベルは新しいドメインになる', () => {
      assert.equal(updateEntry(defaultLabeled, { domain: 'new.example.com' }).label, 'new.example.com');
    });

    test('ラベルを空にしてドメインを変えると、ラベルは新しいドメインになる', () => {
      const updated = updateEntry(defaultLabeled, { label: '', domain: 'new.example.com' });
      assert.equal(updated.label, 'new.example.com');
    });

    test('ドメインを正規化した結果で追従する', () => {
      const updated = updateEntry(defaultLabeled, { label: 'old.example.com', domain: 'HTTPS://New.Example.com/' });
      assert.equal(updated.label, 'new.example.com');
    });

    test('既定のラベルでも、別のラベルを送ればそのラベルを使う', () => {
      const updated = updateEntry(defaultLabeled, { label: '本番', domain: 'new.example.com' });
      assert.equal(updated.label, '本番');
    });

    test('ドメインを変えなければ既定のラベルはそのまま', () => {
      const updated = updateEntry(defaultLabeled, { label: 'old.example.com', username: 'new' });
      assert.equal(updated.label, 'old.example.com');
    });

    test('カスタムのラベルはドメインを変えても維持する', () => {
      const updated = updateEntry(existing, { label: '旧', domain: 'new.example.com' });
      assert.equal(updated.label, '旧');
    });

    test('カスタムのラベルはラベルを省略してドメインを変えても維持する', () => {
      assert.equal(updateEntry(existing, { domain: 'new.example.com' }).label, '旧');
    });
  });
});

describe('toPublicEntry', () => {
  test('パスワードを含めない', () => {
    const entry = createEntry({ domain: 'a.example.com', username: 'u', password: 'p' }, fixedId);
    const publicEntry = toPublicEntry(entry);
    assert.equal('password' in publicEntry, false);
    assert.equal(publicEntry.hasPassword, true);
    assert.equal(publicEntry.domain, 'a.example.com');
  });
});
