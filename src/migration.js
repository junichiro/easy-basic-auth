import { createEntry, assertUniqueDomain, ValidationError } from './entries.js';

function isUsableId(id, usedIds) {
  return typeof id === 'string' && id.length > 0 && !usedIds.has(id);
}

function describeEntry(entry) {
  return entry?.label || entry?.domain || '名前なし';
}

function toMigrationError(error, entry, configPath) {
  return new ValidationError(
    `移行できない登録があります（${describeEntry(entry)}）: ${error.message}。`
    + `${configPath} を直接編集して修正するか、該当の登録を削除してから再度お試しください`,
    error.field,
  );
}

/**
 * 旧形式 (v1・平文) のエントリを、新規登録と同じ検証・正規化に通す。
 * ID が文字列でない・重複している場合は振り直し、ドメインの重複はエラーにする。
 */
export function normalizeLegacyEntries(entries, { generateId, configPath }) {
  const usedIds = new Set();
  return entries.reduce((normalized, entry) => {
    try {
      const id = isUsableId(entry?.id, usedIds) ? entry.id : generateId();
      const candidate = createEntry(entry, () => id);
      assertUniqueDomain(normalized, candidate);
      usedIds.add(id);
      return [...normalized, candidate];
    } catch (error) {
      if (!(error instanceof ValidationError)) throw error;
      throw toMigrationError(error, entry, configPath);
    }
  }, []);
}
