import { db } from "./db";
import { FixedRefillTokenBucket } from "./rate-limit";
import { generateRandomRecoveryCode } from "./utils";

export const totpBucket = new FixedRefillTokenBucket<number>(5, 60 * 30);
export const recoveryCodeBucket = new FixedRefillTokenBucket<number>(5, 60 * 60);

export function resetUser2FAWithRecoveryCode(userId: number, recoveryCode: string): boolean {
	db.execute("UPDATE session SET two_factor_verified = 0 WHERE user_id = ?", [userId]);
	const newRecoveryCode = generateRandomRecoveryCode();
	const result = db.execute("UPDATE user SET recovery_code = ?, totp_key = NULL WHERE id = ? AND recovery_code = ?", [
		newRecoveryCode,
		userId,
		recoveryCode
	]);
	return result.changes > 0;
}
