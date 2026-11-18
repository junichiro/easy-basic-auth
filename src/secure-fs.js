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

// 中身をディスクへ書き出してから閉じる。rename の前に行わないと、停電時に空のファイルが残りうる
function writeAndSync(filePath, content) {
  const fd = fs.openSync(filePath, 'w', FILE_MODE);
  try {
    fs.writeFileSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

// rename をディスクへ確定させる。ディレクトリの fsync に対応しないファイルシステムもあるため、
// 失敗してもファイル自体は置き換わっているので無視する
function syncDirBestEffort(dir) {
  if (!IS_POSIX) return;
  try {
    const fd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch {
    // 何もしない
  }
}

/**
 * 一時ファイルに書いてディスクへ書き出してから rename するアトミック書き込み。
 * POSIX 環境ではファイルを 0600 にする。
 */
export function writeFileAtomic(filePath, content) {
  const dir = path.dirname(filePath);
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`);
  try {
    writeAndSync(tmpPath, content);
    if (IS_POSIX) fs.chmodSync(tmpPath, FILE_MODE);
    fs.renameSync(tmpPath, filePath);
  } catch (error) {
    fs.rmSync(tmpPath, { force: true });
    throw error;
  }
  syncDirBestEffort(dir);
}

export function writeJsonAtomic(filePath, value) {
  writeFileAtomic(filePath, `${JSON.stringify(value, null, 2)}\n`);
}
