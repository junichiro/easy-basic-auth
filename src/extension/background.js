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

// service worker が起動するたびに、ロックの状態とセッションルール・バッジをそろえる。
// 無効化→有効化では storage.session (解除の状態) は消えるのにセッションルールが残り、
// 「ロック中」と表示しながら資格情報を送り続けることがあるため、解除されていなければルールも消す
unlocker.syncLockState();

// ブラウザの起動時と、インストール・更新・再読み込みの時は、リスナーを登録したイベントがなければ
// service worker が起動しない。起動させてロックの状態をそろえるためにリスナーを置く
chrome.runtime.onStartup.addListener(() => unlocker.syncLockState());
chrome.runtime.onInstalled.addListener(() => unlocker.syncLockState());

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  // 非同期で応答するため true を返す
  return true;
});
