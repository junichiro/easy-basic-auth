# edge-basic-auth

Basic 認証がかかった社内サイトなどに、Edge から認証ダイアログなしでアクセスするためのツールです。
ローカルの設定 WebUI で認証情報を登録すると、`Authorization: Basic ...` ヘッダーを付与する Edge（Chromium 系）用の拡張機能（Manifest V3）を生成します。

- 認証情報は**マスターパスワードで暗号化**して保存し、ディスク上に平文を残しません
- 依存パッケージはありません（Node.js 標準モジュールと WebCrypto のみ）

## 使い方

```sh
npm start            # または node src/server.js
```

1. コンソールに表示される `http://127.0.0.1:4729/?token=...` をブラウザで開く
2. 初回はマスターパスワード（12 文字以上）を設定する。1Password などのパスワードマネージャーで生成・保存するのがおすすめです（ユーザー名欄は `edge-basic-auth` 固定）
3. サイトを登録する。保存するたびに拡張機能が再生成されます

### Edge への読み込み

1. `edge://extensions` をアドレスバーに貼り付けて開く
2. **初回**: 「開発者モード」を ON にし、「展開して読み込みます」で UI に表示された出力先フォルダ（`<CONFIG_DIR>/extension`）を指定する。ツールバーにアイコンをピン留めしておくと便利です
3. **2 回目以降**: 設定を保存したら、本拡張の「再読み込み」を押す。拡張機能一覧の version が UI の表示と一致すれば反映済み

### 解除（ブラウザ起動のたびに 1 回）

ブラウザの起動時と拡張機能の再読み込みの後は、アイコンに `LOCK` バッジが付き、認証ヘッダーは付きません。
アイコンをクリックし、マスターパスワードを貼り付けて Enter で解除します（1Password ならクイックアクセス ⌘⇧Space でコピー）。
拡張機能のポップアップにはパスワードマネージャーの自動入力が効かないため、コピー＆ペーストを前提にしています。

## 仕組み

```
[設定 UI] ──マスターパスワード → PBKDF2 で鍵を導出（メモリ上のみ）
   ├─▶ config.json            エントリ全体を AES-256-GCM で暗号化
   └─▶ extension/vault.json   有効なエントリを同じ鍵で暗号化

[拡張機能] ポップアップで入力 → service worker が vault.json を復号
          → declarativeNetRequest のセッションルールに登録（メモリのみ・ブラウザ終了で消える）
```

| 項目 | 値 |
| --- | --- |
| 鍵導出 | PBKDF2-SHA256、2,000,000 回、salt 16 バイト |
| 暗号化 | AES-256-GCM、IV 12 バイト（書き込みごとにランダム） |
| 用途の分離 | AAD に `edge-basic-auth/config/v2` / `edge-basic-auth/extension/v1` |

設定 UI は 15 分間操作がないと自動でロックします。

## 設定の保存先（CONFIG_DIR）

| 環境 | 既定値 |
| --- | --- |
| macOS / Linux | `$XDG_CONFIG_HOME/edge-basic-auth`（未設定なら `~/.config/edge-basic-auth`） |
| Windows | `%APPDATA%\edge-basic-auth` |

環境変数 `EDGE_BASIC_AUTH_DIR` で上書きできます。macOS / Linux ではディレクトリを `0700`、ファイルを `0600` にします。リポジトリには何も出力しません。

旧バージョンの平文の `config.json` がある場合は、初回のマスターパスワード設定時に自動で暗号化して移行し、平文の `rules.json` を削除します。
ただし、以前の平文がバックアップや SSD 上に残っている可能性はあります。

## 環境変数

| 変数 | 説明 | 既定値 |
| --- | --- | --- |
| `PORT` | 設定 UI のポート | `4729` |
| `EDGE_BASIC_AUTH_DIR` | 設定・生成物の保存先 | 上表のとおり |

## セキュリティ

- サーバーは `127.0.0.1` にのみ bind します
- 起動ごとにランダムなアクセストークンを発行し、すべての API で検証します
- `Host` ヘッダーを検証します（DNS リバインディング対策）
- 状態を変える API（POST / PUT / DELETE）では `Origin` を検証します（CSRF 対策）
- CORS ヘッダーは付けません。パスワードは API から返しません
- 「サブドメインを含む」を ON にすると、`*.<domain>` のすべてのホストに認証情報が送られます

### 制約

- **マスターパスワードを忘れると復旧できません**。`config.json` を削除して登録し直してください
- 対象の**ドメイン名**は拡張機能の `manifest.json`（`host_permissions`）に平文で残ります。ユーザー名・パスワード・ラベルは暗号化されます
- 設定 UI のサーバーを、同じ CONFIG_DIR に対して複数同時に起動しないでください（書き込みの排他は 1 プロセス内のみです）
- 解除後の認証情報はブラウザのメモリ上にあります。自分のユーザー権限で動くマルウェアに対する完全な防御にはなりません

## 開発

```sh
npm test             # node:test
```

```
src/
├ server.js            # HTTP サーバー・API・トークン/Host/Origin 検証
├ service.js           # 初期設定・アンロック・エントリの CRUD・保存時の再生成
├ session.js           # 設定 UI のロック状態（鍵はメモリのみ・自動ロック）
├ vault.js             # config.json (v2) の暗号化/復号・v1 判定
├ master-password.js   # マスターパスワードの検証
├ entries.js           # エントリの入力検証・正規化
├ config.js            # CONFIG_DIR 解決、config.json の読み書き
├ generate.js          # manifest.json / vault.json 生成と拡張機能の書き出し
├ secure-fs.js         # アトミック書き込み・パーミッション設定
├ public/              # 設定 UI (index.html, app.js, style.css)
└ extension/           # 生成される拡張機能のソース（そのままコピーされる）
   ├ background.js     # service worker
   ├ popup.*           # 解除用ポップアップ
   └ lib/              # Node と共用: vault-crypto.js, rules.js, unlocker.js
```
