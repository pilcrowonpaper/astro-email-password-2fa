import { generateRandomOTP } from "./utils";
import { db } from "./db";
import { ConstantRefillTokenBucket } from "./rate-limit";

export function verifyEmailInput(email: string): boolean {
	return /^.+@.+\..+$/.test(email) && email.length < 256;
}

export function getUserEmailVerificationRequest(userId: number): EmailVerificationRequest | null {
	const row = db.queryOne("SELECT id, code, email, expires_at FROM email_verification_request WHERE user_id = ?", [
		userId
	]);
	if (row === null) {
		return row;
	}
	const request: EmailVerificationRequest = {
		id: row.number(0),
		userId,
		code: row.string(1),
		email: row.string(2),
		expiresAt: new Date(row.number(3) * 1000)
	};
	return request;
}

export function createEmailVerificationRequest(userId: number, email: string): EmailVerificationRequest {
	deleteUserEmailVerificationRequest(userId);
	const code = generateRandomOTP();
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);
	const row = db.queryOne(
		"INSERT INTO email_verification_request (user_id, code, email, expires_at) VALUES (?, ?, ?, ?) RETURNING id",
		[userId, code, email, Math.floor(expiresAt.getTime() / 1000)]
	);
	if (row === null) {
		throw new Error();
	}
	const request: EmailVerificationRequest = {
		id: row.number(0),
		userId,
		code,
		email,
		expiresAt
	};
	return request;
}

export function deleteUserEmailVerificationRequest(userId: number): void {
	db.execute("DELETE FROM email_verification_request WHERE user_id = ?", [userId]);
}

export function sendVerificationEmail(email: string, code: string): void {
	console.log(`To ${email}: Your verification code is ${code}`);
}

export function checkEmailAvailability(email: string): boolean {
	const row = db.queryOne("SELECT COUNT(*) FROM user WHERE email = ?", [email]);
	if (row === null) {
		throw new Error();
	}
	return row.number(0) === 0;
}

export const sendVerificationEmailBucket = new ConstantRefillTokenBucket<number>(3, 30);

export interface EmailVerificationRequest {
	id: number;
	userId: number;
	code: string;
	email: string;
	expiresAt: Date;
}
