// 初期設定済み/未設定、未対応の設定ファイルなど、現在の状態では実行できない操作
export class StateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateError';
  }
}

// config.json が壊れている、または想定した形式ではない (JSON として読めない、必要な項目が無い・型が違う など)
export class BrokenConfigError extends StateError {
  constructor({ configPath, cause } = {}) {
    const location = configPath ? ` (${configPath})` : '';
    super(`config.json${location} が壊れているか、想定した形式ではありません。ファイルを修正するか、別の場所へ移動してから再度お試しください`);
    this.name = 'BrokenConfigError';
    this.configPath = configPath;
    if (cause !== undefined) this.cause = cause;
  }
}
