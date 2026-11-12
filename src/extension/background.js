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
});

const handleMessage = createMessageHandler(unlocker, chrome.runtime.id);

// ブラウザ起動時・インストール/再読み込み時はセッションルールが空なので、ロック表示にする
chrome.runtime.onStartup.addListener(() => unlocker.refreshBadge());
chrome.runtime.onInstalled.addListener(() => unlocker.refreshBadge());

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse);
  // 非同期で応答するため true を返す
  return true;
});
