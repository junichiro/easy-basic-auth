// Node と拡張機能の両方で使うため、Node 固有の API は使わない

/**
 * 非同期の処理が交互に実行されないよう、受け付けた順に 1 つずつ実行する関数を返す。
 * 前の処理が失敗しても、後続の処理は実行する。
 */
export function createMutex() {
  let tail = Promise.resolve();
  return (task) => {
    const run = tail.then(task);
    tail = run.catch(() => {});
    return run;
  };
}
