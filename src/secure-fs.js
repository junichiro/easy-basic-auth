import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const DIR_MODE = 0o700;
const FILE_MODE = 0o600;
const IS_POSIX = process.platform !== 'win32';

/**
 * ディレクトリを作成し、POSIX 環境では所有者のみアクセス可能 (0700) にする。
 * 既存ディレクトリのパーミッションも締め直す。
 */
export function ensurePrivateDir(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: DIR_MODE });
  if (IS_POSIX) fs.chmodSync(dir, DIR_MODE);
}

/**
 * 一時ファイルに書いてから rename するアトミック書き込み。
 * POSIX 環境ではファイルを 0600 にする。
 */
export function writeFileAtomic(filePath, content) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`);
  try {
    fs.writeFileSync(tmpPath, content, { mode: FILE_MODE });
    if (IS_POSIX) fs.chmodSync(tmpPath, FILE_MODE);
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
}

export function writeJsonAtomic(filePath, value) {
  writeFileAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);
}
