import { ValidationError } from './entries.js';

export const MIN_MASTER_PASSWORD_LENGTH = 12;

export function validateMasterPassword(password, field = 'masterPassword') {
  if (typeof password !== 'string') {
    throw new ValidationError('マスターパスワードを入力してください', field);
  }
  // 絵文字などのサロゲートペアも 1 文字として数える
  if ([...password].length < MIN_MASTER_PASSWORD_LENGTH) {
    throw new ValidationError(
      `マスターパスワードは ${MIN_MASTER_PASSWORD_LENGTH} 文字以上にしてください（長めのパスフレーズを推奨）`,
      field,
    );
  }
  return password;
}
