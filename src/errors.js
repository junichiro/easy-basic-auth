// 初期設定済み/未設定、未対応の設定ファイルなど、現在の状態では実行できない操作
export class StateError extends Error {
  constructor(message) {
    super(message);
    this.name = 'StateError';
  }
}
