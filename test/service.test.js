import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createEntryService, StateError } from '../src/service.js';
import { createSession, LockedError } from '../src/session.js';
import { ValidationError } from '../src/entries.js';
import { UnsupportedConfigError } from '../src/vault.js';
import { deriveKey, decryptJson, VAULT_AAD, DecryptionError } from '../src/extension/lib/vault-crypto.js';

const MASTER = 'master password 1234';
const SECRET_USER = 'distinctive-user-name';
const SECRET_PASSWORD = 'distinctive-secret-パスワード';
const SECRET_LABEL = 'distinctive-label';

function makeService({ now } = {}) {
  const configDir = fs.mkdtempSync(path.join(os.tmpdir(), 'eba-service-'));
  const session = createSession({ idleTimeoutMs: 60_000, now });
  const service = createEntryService({ configDir, session, kdfIterations: 1000 });
  return { configDir, session, service };
}

const entryInput = {
  label: SECRET_LABEL,
  domain: 'secure.example.com',
  username: SECRET_USER,
  password: SECRET_PASSWORD,
};

function readJson(...segments) {
  return JSON.parse(fs.readFileSync(path.join(...segments), 'utf8'));
}

function listFilesRecursively(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((dirent) => {
    const fullPath = path.join(dir, dirent.name);
    return dirent.isDirectory() ? listFilesRecursively(fullPath) : [fullPath];
  });
}

async function decryptExtensionVault(configDir, masterPassword) {
  const vault = readJson(configDir, 'extension', 'vault.json');
  const key = await deriveKey(masterPassword, vault.kdf);
  return decryptJson(key, vault, VAULT_AAD.extension);
}

describe('初期設定', () => {
  test('最初は未初期化かつロック中', async () => {
    const { service } = makeService();
    assert.deepEqual(service.getStatus(), { initialized: false, unlocked: false, needsMigration: false, minMasterPasswordLength: 12 });
  });

  test('未初期化のままエントリ操作はできない', async () => {
    const { service } = makeService();
    await assert.rejects(service.getState(), LockedError);
  });

  test('短いマスターパスワードは拒否する', async () => {
    const { service } = makeService();
    await assert.rejects(service.setup('short'), ValidationError);
  });

  test('マスターパスワードを設定すると暗号化された config と拡張機能を生成し、アンロック状態になる', async () => {
    const { service, configDir } = makeService();
    await service.setup(MASTER);
    assert.deepEqual(service.getStatus(), { initialized: true, unlocked: true, needsMigration: false, minMasterPasswordLength: 12 });
    assert.equal(readJson(configDir, 'config.json').version, 2);
    assert.deepEqual(await decryptExtensionVault(configDir, MASTER), { entries: [] });
  });

  test('初期化済みなら再度の初期設定はできない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await assert.rejects(service.setup(MASTER), StateError);
  });
});

describe('ロックとアンロック', () => {
  test('ロック中はエントリ操作ができない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    service.lock();
    await assert.rejects(service.getState(), LockedError);
    await assert.rejects(service.addEntry(entryInput), LockedError);
  });

  test('誤ったマスターパスワードではアンロックできない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    service.lock();
    await assert.rejects(service.unlock('wrong password!!'), ValidationError);
    assert.equal(service.getStatus().unlocked, false);
  });

  test('正しいマスターパスワードでアンロックできる', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await service.addEntry(entryInput);
    service.lock();
    await service.unlock(MASTER);
    const state = await service.getState();
    assert.equal(state.entries[0].username, SECRET_USER);
  });

  test('未初期化ではアンロックできない', async () => {
    const { service } = makeService();
    await assert.rejects(service.unlock(MASTER), StateError);
  });

  test('別プロセスでマスターパスワードが変わり鍵が合わなくなったら、ロック扱いにする', async () => {
    const { service, configDir } = makeService();
    await service.setup(MASTER);
    const other = createEntryService({ configDir, session: createSession(), kdfIterations: 1000 });
    await other.changeMasterPassword(MASTER, 'changed elsewhere 123');

    await assert.rejects(service.getState(), (error) => error instanceof LockedError
      && error.message.includes('マスターパスワードが変更されたか') && error.message.includes('破損'));
    assert.equal(service.getStatus().unlocked, false);
  });

  test('解除処理中にロックされたら、解除が後から完了してもロックのままにする', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    service.lock();
    const pending = service.unlock(MASTER);
    service.lock();
    await pending;
    assert.equal(service.getStatus().unlocked, false);
  });

  test('マスターパスワード変更中にロックされたら、変更は保存するがロックのままにする', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    const pending = service.changeMasterPassword(MASTER, 'next master password 5678');
    service.lock();
    await pending;
    assert.equal(service.getStatus().unlocked, false);
    await service.unlock('next master password 5678');
    assert.equal(service.getStatus().unlocked, true);
  });

  test('マスターパスワード変更と旧パスワードでのアンロックが同時に来ても、古い鍵が残らない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await Promise.allSettled([
      service.changeMasterPassword(MASTER, 'next master password 5678'),
      service.unlock(MASTER),
    ]);
    await assert.doesNotReject(service.getState());
  });

  test('一定時間操作がなければ自動でロックされる', async () => {
    let current = 0;
    const { service } = makeService({ now: () => current });
    await service.setup(MASTER);
    current += 60_001;
    assert.equal(service.getStatus().unlocked, false);
    await assert.rejects(service.getState(), LockedError);
  });
});

describe('エントリ操作と生成', () => {
  test('エントリを追加すると拡張機能の vault が更新され version が上がる', async () => {
    const { service, configDir } = makeService();
    await service.setup(MASTER);
    const state = await service.addEntry(entryInput);
    assert.equal(state.extensionVersion, '1.0.2');
    assert.equal(state.entries[0].password, undefined);

    const { entries } = await decryptExtensionVault(configDir, MASTER);
    assert.deepEqual(entries, [{
      domain: 'secure.example.com', includeSubdomains: false, username: SECRET_USER, password: SECRET_PASSWORD,
    }]);
  });

  test('ディスク上のどのファイルにも認証情報が平文で残らない', async () => {
    const { service, configDir } = makeService();
    await service.setup(MASTER);
    await service.addEntry(entryInput);
    await service.addEntry({ ...entryInput, domain: 'other.example.com', includeSubdomains: true });

    const forbidden = [
      SECRET_USER,
      SECRET_PASSWORD,
      SECRET_LABEL,
      MASTER,
      Buffer.from(`${SECRET_USER}:${SECRET_PASSWORD}`).toString('base64'),
    ];
    for (const file of listFilesRecursively(configDir)) {
      const content = fs.readFileSync(file, 'utf8');
      for (const secret of forbidden) {
        assert.ok(!content.includes(secret), `${file} に ${secret} が含まれている`);
      }
    }
  });

  test('同じドメインのエントリは重複登録できない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await service.addEntry(entryInput);
    await assert.rejects(service.addEntry(entryInput), ValidationError);
  });

  test('同時に保存しても更新が失われない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await Promise.all([
      service.addEntry({ ...entryInput, domain: 'a.example.com' }),
      service.addEntry({ ...entryInput, domain: 'b.example.com' }),
      service.addEntry({ ...entryInput, domain: 'c.example.com' }),
    ]);
    assert.equal((await service.getState()).entries.length, 3);
  });
});

describe('マスターパスワードの変更', () => {
  const NEXT = 'next master password 5678';

  test('現在のパスワードが違えば変更できない', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await assert.rejects(service.changeMasterPassword('wrong password!!', NEXT), ValidationError);
  });

  test('新しいパスワードも最低文字数を満たす必要がある', async () => {
    const { service } = makeService();
    await service.setup(MASTER);
    await assert.rejects(service.changeMasterPassword(MASTER, 'short'), ValidationError);
  });

  test('変更後は新しいパスワードで config と拡張機能を開ける', async () => {
    const { service, configDir } = makeService();
    await service.setup(MASTER);
    await service.addEntry(entryInput);
    await service.changeMasterPassword(MASTER, NEXT);

    service.lock();
    await assert.rejects(service.unlock(MASTER), ValidationError);
    await service.unlock(NEXT);
    assert.equal((await service.getState()).entries.length, 1);

    await assert.rejects(decryptExtensionVault(configDir, MASTER), DecryptionError);
    assert.equal((await decryptExtensionVault(configDir, NEXT)).entries.length, 1);
  });
});

describe('未対応の config', () => {
  test('未知のバージョンの config は UnsupportedConfigError にする', () => {
    const { service, configDir } = makeService();
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ version: 99 }));
    assert.throws(() => service.getStatus(), UnsupportedConfigError);
  });
});

describe('v1 (平文) からの移行', () => {
  function writeLegacyConfig(configDir) {
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      extensionVersionCounter: 7,
      entries: [{
        id: 'legacy-id', ...entryInput, includeSubdomains: false, enabled: true,
      }],
    }));
    fs.mkdirSync(path.join(configDir, 'extension'));
    fs.writeFileSync(path.join(configDir, 'extension', 'rules.json'), `["${SECRET_PASSWORD}"]`);
  }

  test('平文の config があれば移行が必要と報告する', () => {
    const { service, configDir } = makeService();
    writeLegacyConfig(configDir);
    assert.deepEqual(service.getStatus(), { initialized: false, unlocked: false, needsMigration: true, minMasterPasswordLength: 12 });
  });

  test('移行するエントリも検証・正規化する（ID・enabled の補完、ドメインの小文字化）', async () => {
    const { service, configDir } = makeService();
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      extensionVersionCounter: 1,
      entries: [{ domain: 'HTTPS://Legacy.Example.com/', username: 'u', password: 'p' }],
    }));
    const { entries: [entry] } = await service.setup(MASTER);
    assert.equal(entry.domain, 'legacy.example.com');
    assert.equal(entry.enabled, true);
    assert.equal(typeof entry.id, 'string');
    assert.ok(entry.id.length > 0);
  });

  test('移行するエントリの ID が文字列でない・重複している場合は振り直す', async () => {
    const { service, configDir } = makeService();
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      extensionVersionCounter: 1,
      entries: [
        { id: 3, domain: 'a.example.com', username: 'u', password: 'p' },
        { id: 'dup', domain: 'b.example.com', username: 'u', password: 'p' },
        { id: 'dup', domain: 'c.example.com', username: 'u', password: 'p' },
      ],
    }));
    const { entries } = await service.setup(MASTER);
    const ids = entries.map((entry) => entry.id);
    assert.ok(ids.every((id) => typeof id === 'string' && id.length > 0));
    assert.equal(new Set(ids).size, 3);
    assert.equal(ids[1], 'dup');
  });

  test('移行するエントリのドメインが重複していればエラーにする', async () => {
    const { service, configDir } = makeService();
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      extensionVersionCounter: 1,
      entries: [
        { label: '一つ目', domain: 'a.example.com', username: 'u', password: 'p' },
        { label: '二つ目', domain: 'A.example.com', username: 'u', password: 'p' },
      ],
    }));
    await assert.rejects(service.setup(MASTER), (error) => error instanceof ValidationError && error.message.includes('二つ目'));
  });

  test('移行するエントリが不正なら、どのエントリかわかるエラーにする', async () => {
    const { service, configDir } = makeService();
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({
      version: 1,
      extensionVersionCounter: 1,
      entries: [{ label: '壊れた登録', domain: '', username: 'u', password: 'p' }],
    }));
    await assert.rejects(service.setup(MASTER), (error) => error instanceof ValidationError
      && error.message.includes('壊れた登録')
      && error.message.includes(path.join(configDir, 'config.json')));
  });

  test('初期設定で既存エントリを暗号化し、平文の rules.json を削除する', async () => {
    const { service, configDir } = makeService();
    writeLegacyConfig(configDir);
    const state = await service.setup(MASTER);

    assert.equal(state.entries[0].id, 'legacy-id');
    assert.equal(state.extensionVersion, '1.0.8');
    assert.equal(fs.existsSync(path.join(configDir, 'extension', 'rules.json')), false);
    for (const file of listFilesRecursively(configDir)) {
      assert.ok(!fs.readFileSync(file, 'utf8').includes(SECRET_PASSWORD), file);
    }
  });
});
