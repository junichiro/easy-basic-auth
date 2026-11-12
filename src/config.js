import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ensurePrivateDir, writeJsonAtomic } from './secure-fs.js';

const APP_DIR_NAME = 'edge-basic-auth';
const CONFIG_FILE_NAME = 'config.json';

/**
 * 設定ディレクトリ (CONFIG_DIR) を解決する純粋関数。
 * 優先順位: EDGE_BASIC_AUTH_DIR > (Windows) APPDATA > XDG_CONFIG_HOME > ~/.config
 */
export function resolveConfigDir({
  env = process.env,
  platform = process.platform,
  homedir = os.homedir(),
} = {}) {
  if (env.EDGE_BASIC_AUTH_DIR) return path.resolve(env.EDGE_BASIC_AUTH_DIR);
  if (platform === 'win32') {
    return path.join(env.APPDATA || path.join(homedir, 'AppData', 'Roaming'), APP_DIR_NAME);
  }
  return path.join(env.XDG_CONFIG_HOME || path.join(homedir, '.config'), APP_DIR_NAME);
}

export function getExtensionDir(configDir) {
  return path.join(configDir, 'extension');
}

export function readConfig(configDir) {
  const filePath = path.join(configDir, CONFIG_FILE_NAME);
  if (!fs.existsSync(filePath)) return null;

  const raw = fs.readFileSync(filePath, 'utf8');
  try {
    return JSON.parse(raw);
  } catch (error) {
    throw new Error(`Failed to parse ${filePath}: ${error.message}`, { cause: error });
  }
}

export function writeConfig(configDir, config) {
  ensurePrivateDir(configDir);
  writeJsonAtomic(path.join(configDir, CONFIG_FILE_NAME), config);
}
