import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { validateMasterPassword, MIN_MASTER_PASSWORD_LENGTH } from '../src/master-password.js';
import { ValidationError } from '../src/entries.js';

describe('validateMasterPassword', () => {
  test('最低文字数は 12 文字', () => {
    assert.equal(MIN_MASTER_PASSWORD_LENGTH, 12);
  });

  test('12 文字以上なら受け付ける', () => {
    assert.equal(validateMasterPassword('a'.repeat(12)), 'a'.repeat(12));
  });

  test('12 文字未満は拒否する', () => {
    assert.throws(() => validateMasterPassword('a'.repeat(11)), ValidationError);
  });

  test('文字数はコードポイント単位で数える', () => {
    assert.throws(() => validateMasterPassword('🔑'.repeat(6)), ValidationError);
    assert.doesNotThrow(() => validateMasterPassword('🔑'.repeat(12)));
  });

  test('文字列以外は拒否する', () => {
    assert.throws(() => validateMasterPassword(undefined), ValidationError);
    assert.throws(() => validateMasterPassword(123456789012), ValidationError);
  });
});
