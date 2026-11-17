// 「サブドメインを含む」を付けると、他者のサイトにまで認証情報が送られてしまうドメインの判定。
// 依存パッケージを使わないため、Public Suffix List 全体ではなく、よく使われるものだけを持つ。
// 一覧にないものは画面の警告で注意を促す

// 国別 TLD の下で、登録者に割り当てられる第 2 レベル (co.jp・co.uk・com.au など)
const COUNTRY_SECOND_LEVELS = new Set([
  'ac', 'co', 'com', 'ed', 'edu', 'go', 'gov', 'gr', 'lg', 'ltd', 'mil', 'ne', 'net', 'nom', 'or', 'org', 'plc', 'sch',
]);

// 利用者ごとにサブドメインが割り当てられる共有ホスティング (事業者が共有する下の階層も含む)
const SHARED_HOSTING_SUFFIXES = new Set([
  'amazonaws.com', 'appspot.com', 'azurestaticapps.net', 'azurewebsites.net', 'blogspot.com',
  'cloudapp.net', 'cloudfront.net', 'firebaseapp.com', 'fly.dev', 'github.io', 'gitlab.io',
  'glitch.me', 'herokuapp.com', 'netlify.app', 'ngrok.io', 'ngrok-free.app', 'onrender.com',
  'pages.dev', 'readthedocs.io', 'run.app', 'trafficmanager.net', 'vercel.app', 'web.app', 'workers.dev',
  'a.run.app', 'r.appspot.com', 's3.amazonaws.com', 'elb.amazonaws.com', 'compute.amazonaws.com',
  'cloudfunctions.net', 'azureedge.net', 'azurefd.net', 'blob.core.windows.net', 'web.core.windows.net',
]);

// サブドメインを持てる 1 ラベルの名前。*.localhost はループバックに解決され、
// ほかは社内・家庭内のネットワークで使われる (インターネットの TLD ではない)
const LOCAL_SINGLE_LABELS = new Set(['localhost', 'internal', 'corp', 'home', 'lan', 'local', 'intranet']);

function isCountrySecondLevel(labels) {
  return labels.length === 2 && labels[1].length === 2 && COUNTRY_SECOND_LEVELS.has(labels[0]);
}

/**
 * 正規化済みのホスト名が公開サフィックス (TLD・co.jp・github.io など) かを判定する。
 */
export function isPublicSuffix(hostname) {
  const labels = hostname.split('.');
  if (labels.length === 1) return !LOCAL_SINGLE_LABELS.has(hostname);
  return isCountrySecondLevel(labels) || SHARED_HOSTING_SUFFIXES.has(hostname);
}
