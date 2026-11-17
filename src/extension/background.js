import { createUnlocker, createMessageHandler } from './lib/unlocker.js';

const unlocker = createUnlocker({
  dnr: chrome.declarativeNetRequest,
  storage: chrome.storage.session,
  action: chrome.action,
  loadVault: async () => {
    const res = await fetch(chrome.runtime.getURL('vault.json'));
    if (!res.ok) throw new Error(`vault.json を読み込めませんでした (${res.status})`);
    return res.json();
  },
  manifestVersion: chrome.runtime.getManifest().version,
});

const handleMessage = createMessageHandler(unlocker, chrome.runtime.id);

// service worker が起動するたびにバッジを状態に合わせる。インストール・再読み込みに加え、
// 無効化→有効化のように onStartup / onInstalled が発火せずにセッションルールが消える場合も、ロック表示にする
unlocker.refreshBadge();

// ブラウザの起動時は、リスナーを登録したイベントがなければ service worker が起動しない。
// バッジはブラウザを閉じると消えるため、起動時にロック表示に戻すにはこのリスナーが要る
chrome.runtime.onStartup.addListener(() => unlocker.refreshBadge());

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  // 非同期で応答するため true を返す
  return true;
});
