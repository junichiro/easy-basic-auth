const elements = {
  statusText: document.getElementById('status-text'),
  version: document.getElementById('version'),
  unlockForm: document.getElementById('unlock-form'),
  password: document.getElementById('password'),
  unlockButton: document.getElementById('unlock-button'),
  unlockedPanel: document.getElementById('unlocked-panel'),
  lockButton: document.getElementById('lock-button'),
  error: document.getElementById('error'),
};

function showError(message) {
  elements.error.textContent = message ?? '';
  elements.error.hidden = !message;
}

function render({ unlocked }) {
  elements.statusText.textContent = unlocked ? '🔓 解除済み' : '🔒 ロック中';
  elements.unlockForm.hidden = unlocked;
  elements.unlockedPanel.hidden = !unlocked;
  if (!unlocked) elements.password.focus();
}

async function send(message) {
  const response = await chrome.runtime.sendMessage(message);
  if (!response) {
    throw new Error('拡張機能のバックグラウンド処理が応答しません。edge://extensions で再読み込みしてください。');
  }
  if (response.ok === false) throw new Error(response.error);
  return response;
}

async function refresh() {
  try {
    render(await send({ type: 'status' }));
  } catch (error) {
    showError(error.message);
  }
}

async function unlock(event) {
  event.preventDefault();
  showError('');
  elements.unlockButton.disabled = true;
  elements.unlockButton.textContent = '解除中…';
  try {
    await send({ type: 'unlock', password: elements.password.value });
    elements.password.value = '';
    await refresh();
  } catch (error) {
    showError(error.message);
    elements.password.select();
  } finally {
    elements.unlockButton.disabled = false;
    elements.unlockButton.textContent = '解除';
  }
}

async function lock() {
  showError('');
  try {
    await send({ type: 'lock' });
    await refresh();
  } catch (error) {
    showError(error.message);
  }
}

elements.version.textContent = `v${chrome.runtime.getManifest().version}`;
elements.unlockForm.addEventListener('submit', unlock);
elements.lockButton.addEventListener('click', lock);
refresh();
