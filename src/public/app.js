const TOKEN_STORAGE_KEY = 'edge-basic-auth-token';

const byId = (id) => document.getElementById(id);

const elements = {
  globalError: byId('global-error'),
  globalNotice: byId('global-notice'),
  lockButton: byId('lock-button'),
  setupView: byId('setup-view'),
  setupForm: byId('setup-form'),
  migrationNotice: byId('migration-notice'),
  unlockView: byId('unlock-view'),
  unlockForm: byId('unlock-form'),
  mainView: byId('main-view'),
  changeForm: byId('change-form'),
  entriesTable: byId('entries-table'),
  entriesBody: byId('entries-body'),
  entriesEmpty: byId('entries-empty'),
  formSection: byId('form-section'),
  formTitle: byId('form-title'),
  form: byId('entry-form'),
  formError: byId('form-error'),
  passwordHint: byId('password-hint'),
  passwordRequired: byId('password-required'),
  subdomainCheckbox: byId('field-include-subdomains'),
  subdomainWarning: byId('subdomain-warning'),
  subdomainWarningDomain: byId('subdomain-warning-domain'),
  domainInput: byId('field-domain'),
  extensionDir: byId('extension-dir'),
  extensionVersion: byId('extension-version'),
  subdomainNotice: byId('subdomain-notice'),
  subdomainNoticeList: byId('subdomain-notice-list'),
};

let status = { initialized: false, unlocked: false, needsMigration: false, minMasterPasswordLength: 0 };
let state = { entries: [] };
let editingId = null;

// URL のトークンを sessionStorage に移し、アドレスバー・履歴から消す
function takeToken() {
  const url = new URL(window.location.href);
  const fromUrl = url.searchParams.get('token');
  if (fromUrl) {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, fromUrl);
    url.searchParams.delete('token');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  }
  return sessionStorage.getItem(TOKEN_STORAGE_KEY);
}

const token = takeToken();

// ---- 表示ヘルパー ----

function showMessage(element, message) {
  element.textContent = message ?? '';
  element.hidden = !message;
}

const showError = (message) => showMessage(elements.globalError, message);
const showNotice = (message) => showMessage(elements.globalNotice, message);

function formErrorOf(form) {
  return form.querySelector('.form-error');
}

// ---- API ----

function handleLocked(message) {
  status = { ...status, unlocked: false };
  closeForm();
  renderView();
  showError(message);
}

async function callApi(method, path, body) {
  const headers = { Authorization: `Bearer ${token}` };
  if (body !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const payload = await res.json().catch(() => ({}));
  if (res.status === 401) {
    throw new Error('トークンが無効です。サーバーのコンソールに表示された URL を開き直してください。');
  }
  if (res.status === 423) {
    handleLocked('一定時間操作がなかったためロックしました。マスターパスワードで解除してください。');
  }
  if (!res.ok) throw new Error(payload.error || `リクエストに失敗しました (${res.status})`);
  return payload;
}

// ---- 画面の切り替え ----

function renderView() {
  const { initialized, unlocked, needsMigration, minMasterPasswordLength } = status;
  document.querySelectorAll('.min-password-length').forEach((element) => {
    element.textContent = String(minMasterPasswordLength);
  });
  elements.setupView.hidden = initialized;
  elements.migrationNotice.hidden = !needsMigration;
  elements.unlockView.hidden = !initialized || unlocked;
  elements.mainView.hidden = !unlocked;
  elements.lockButton.hidden = !unlocked;

  if (!initialized) elements.setupForm.elements.newPassword.focus();
  else if (!unlocked) elements.unlockForm.elements.masterPassword.focus();
}

async function loadStatus() {
  status = await callApi('GET', '/api/status');
  renderView();
  if (status.unlocked) await refresh();
}

// ---- エントリ一覧 ----

function createCell(content) {
  const cell = document.createElement('td');
  if (content instanceof Node) cell.append(content);
  else cell.textContent = content;
  return cell;
}

function createButton(label, className, onClick) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = `button button-small ${className}`;
  button.textContent = label;
  button.addEventListener('click', onClick);
  return button;
}

function createToggle(entry) {
  const toggle = document.createElement('input');
  toggle.type = 'checkbox';
  toggle.checked = entry.enabled;
  toggle.setAttribute('aria-label', `${entry.label} を有効にする`);
  toggle.addEventListener('change', () => {
    runAction(() => callApi('PUT', `/api/entries/${encodeURIComponent(entry.id)}`, { enabled: toggle.checked }),
      `${entry.label} を${toggle.checked ? '有効' : '無効'}にしました。拡張機能を再読み込みしてください。`);
  });
  return toggle;
}

function createActions(entry) {
  const wrap = document.createElement('div');
  wrap.className = 'row-actions';
  wrap.append(
    createButton('編集', '', () => openForm(entry)),
    createButton('削除', 'button-danger', () => deleteEntry(entry)),
  );
  return wrap;
}

function createEntryRow(entry) {
  const row = document.createElement('tr');
  if (!entry.enabled) row.className = 'is-disabled';
  row.append(
    createCell(createToggle(entry)),
    createCell(entry.label),
    createCell(entry.domain),
    createCell(entry.includeSubdomains ? '含む' : '—'),
    createCell(entry.username),
    createCell(entry.hasPassword ? '••••••••' : '(未設定)'),
    createCell(createActions(entry)),
  );
  return row;
}

function renderEntries() {
  const hasEntries = state.entries.length > 0;
  elements.entriesTable.hidden = !hasEntries;
  elements.entriesEmpty.hidden = hasEntries;
  elements.entriesBody.replaceChildren(...state.entries.map(createEntryRow));
}

function renderResult() {
  elements.extensionDir.textContent = state.extensionDir ?? '';
  elements.extensionVersion.textContent = state.extensionVersion ?? '未生成（保存または再生成で作成されます）';

  const wide = state.entries.filter((entry) => entry.enabled && entry.includeSubdomains);
  elements.subdomainNotice.hidden = wide.length === 0;
  elements.subdomainNoticeList.replaceChildren(...wide.map((entry) => {
    const item = document.createElement('li');
    item.textContent = `${entry.label}: ${entry.domain} と *.${entry.domain}`;
    return item;
  }));
}

function renderState() {
  renderEntries();
  renderResult();
}

async function refresh() {
  try {
    state = await callApi('GET', '/api/state');
    renderState();
  } catch (error) {
    showError(error.message);
  }
}

async function runAction(action, successMessage) {
  showError('');
  try {
    state = await action();
    renderState();
    showNotice(successMessage);
  } catch (error) {
    showError(error.message);
    if (status.unlocked) await refresh();
  }
}

// ---- エントリの追加・編集フォーム ----

function updateSubdomainWarning() {
  elements.subdomainWarning.hidden = !elements.subdomainCheckbox.checked;
  elements.subdomainWarningDomain.textContent = elements.domainInput.value.trim() || '<domain>';
}

function openForm(entry) {
  editingId = entry?.id ?? null;
  elements.form.reset();
  showMessage(elements.formError, '');
  elements.formTitle.textContent = entry ? `「${entry.label}」を編集` : 'サイトを追加';
  elements.passwordHint.hidden = !entry;
  elements.passwordRequired.hidden = Boolean(entry);

  if (entry) {
    elements.form.elements.label.value = entry.label;
    elements.form.elements.domain.value = entry.domain;
    elements.form.elements.includeSubdomains.checked = entry.includeSubdomains;
    elements.form.elements.username.value = entry.username;
  }
  updateSubdomainWarning();
  elements.formSection.hidden = false;
  elements.form.elements.label.focus();
}

function closeForm() {
  editingId = null;
  elements.form.reset();
  elements.formSection.hidden = true;
}

function readEntryForm() {
  const fields = elements.form.elements;
  return {
    label: fields.label.value,
    domain: fields.domain.value,
    includeSubdomains: fields.includeSubdomains.checked,
    username: fields.username.value,
    password: fields.password.value,
  };
}

async function submitEntryForm(event) {
  event.preventDefault();
  showMessage(elements.formError, '');
  const input = readEntryForm();
  try {
    state = editingId
      ? await callApi('PUT', `/api/entries/${encodeURIComponent(editingId)}`, input)
      : await callApi('POST', '/api/entries', input);
  } catch (error) {
    showMessage(elements.formError, error.message);
    return;
  }
  closeForm();
  renderState();
  showNotice(`保存して version ${state.extensionVersion} を生成しました。Edge で拡張機能を再読み込みし、解除してください。`);
}

function deleteEntry(entry) {
  // ブラウザ標準の confirm で誤操作を防ぐ
  if (!window.confirm(`「${entry.label}」(${entry.domain}) を削除しますか？`)) return;
  runAction(() => callApi('DELETE', `/api/entries/${encodeURIComponent(entry.id)}`),
    `「${entry.label}」を削除しました。拡張機能を再読み込みしてください。`);
}

// ---- マスターパスワード関連のフォーム ----

// 最低文字数はサーバーの値に合わせる（最終的な検証はサーバー側で行う）
function validateNewPassword(newPassword, confirmPassword) {
  const minLength = status.minMasterPasswordLength;
  if ([...newPassword].length < minLength) {
    return `マスターパスワードは ${minLength} 文字以上にしてください`;
  }
  if (newPassword !== confirmPassword) return '確認用のパスワードが一致しません';
  return null;
}

// フォーム送信の共通処理: エラー表示・二重送信防止・パスワード欄のクリア
function bindCredentialForm(form, { validate, submit }) {
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const errorElement = formErrorOf(form);
    showMessage(errorElement, '');
    const validationError = validate?.(form.elements);
    if (validationError) {
      showMessage(errorElement, validationError);
      return;
    }

    const button = form.querySelector('button[type="submit"]');
    button.disabled = true;
    try {
      await submit(form.elements);
      form.querySelectorAll('input[type="password"]').forEach((input) => { input.value = ''; });
    } catch (error) {
      showMessage(errorElement, error.message);
    } finally {
      button.disabled = false;
    }
  });
}

function bindSetupForm() {
  bindCredentialForm(elements.setupForm, {
    validate: (fields) => validateNewPassword(fields.newPassword.value, fields.confirmPassword.value),
    submit: async (fields) => {
      const migrated = status.needsMigration;
      state = await callApi('POST', '/api/setup', { masterPassword: fields.newPassword.value });
      status = { ...status, initialized: true, unlocked: true, needsMigration: false };
      renderView();
      renderState();
      showNotice(migrated
        ? '既存の登録を暗号化して移行しました。Edge で拡張機能を再読み込みし、マスターパスワードで解除してください。以前の平文がバックアップ等に残っている可能性があるため、気になる場合は各サイトのパスワード変更を検討してください。'
        : 'マスターパスワードを設定しました。');
    },
  });
}

function bindUnlockForm() {
  bindCredentialForm(elements.unlockForm, {
    submit: async (fields) => {
      status = await callApi('POST', '/api/unlock', { masterPassword: fields.masterPassword.value });
      showError('');
      renderView();
      await refresh();
    },
  });
}

function bindChangeForm() {
  bindCredentialForm(elements.changeForm, {
    validate: (fields) => validateNewPassword(fields.newPassword.value, fields.confirmPassword.value),
    submit: async (fields) => {
      state = await callApi('POST', '/api/master-password', {
        currentPassword: fields.currentPassword.value,
        newPassword: fields.newPassword.value,
      });
      renderState();
      elements.changeForm.closest('details').open = false;
      showNotice(`マスターパスワードを変更し、version ${state.extensionVersion} を生成しました。Edge で拡張機能を再読み込みし、新しいパスワードで解除してください。`);
    },
  });
}

// ---- その他 ----

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const original = button.textContent;
    button.textContent = 'コピーしました';
    setTimeout(() => { button.textContent = original; }, 1500);
  } catch {
    showError('クリップボードにコピーできませんでした。手動で選択してコピーしてください。');
  }
}

async function lock() {
  try {
    status = await callApi('POST', '/api/lock');
    state = { entries: [] };
    closeForm();
    renderView();
    showNotice('');
  } catch (error) {
    showError(error.message);
  }
}

function bindEvents() {
  bindSetupForm();
  bindUnlockForm();
  bindChangeForm();
  elements.lockButton.addEventListener('click', lock);
  byId('add-button').addEventListener('click', () => openForm(null));
  byId('cancel-button').addEventListener('click', closeForm);
  byId('generate-button').addEventListener('click', () => {
    runAction(() => callApi('POST', '/api/generate'),
      '再生成しました。Edge で拡張機能を再読み込みし、解除してください。');
  });
  elements.form.addEventListener('submit', submitEntryForm);
  elements.subdomainCheckbox.addEventListener('change', updateSubdomainWarning);
  elements.domainInput.addEventListener('input', updateSubdomainWarning);
  document.querySelectorAll('[data-copy-target]').forEach((button) => {
    button.addEventListener('click', () => copyText(byId(button.dataset.copyTarget).textContent, button));
  });
}

bindEvents();
if (token) {
  loadStatus().catch((error) => showError(error.message));
} else {
  showError('アクセストークンがありません。サーバー起動時にコンソールへ表示された URL（?token=... 付き）を開いてください。');
}
