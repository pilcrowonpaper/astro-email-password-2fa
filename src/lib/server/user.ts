import { db } from "./db";
import { decrypt, decryptToString, encrypt, encryptString } from "./encryption";
import { hashPassword } from "./password";
import { generateRandomRecoveryCode } from "./utils";

export function verifyUsernameInput(username: string): boolean {
	return username.length > 3 && username.length < 32 && username.trim() === username;
}

export async function createUser(email: string, username: string, password: string): Promise<User> {
	const passwordHash = await hashPassword(password);
	const recoveryCode = generateRandomRecoveryCode();
	const encryptedRecoveryCode = encryptString(recoveryCode);
	const row = db.queryOne(
		"INSERT INTO user (email, username, password_hash, recovery_code) VALUES (?, ?, ?, ?) RETURNING user.id",
		[email, username, passwordHash, encryptedRecoveryCode]
	);
	if (row === null) {
		throw new Error("Unexpected error");
	}
	const user: User = {
		id: row.number(0),
		username,
		email,
		emailVerified: false,
		registered2FA: false
	};
	return user;
}

export async function updateUserPassword(userId: number, password: string): Promise<void> {
	const passwordHash = await hashPassword(password);
	db.execute("UPDATE user SET password_hash = ? WHERE id = ?", [passwordHash, userId]);
}

export function updateUserEmailAndSetEmailAsVerified(userId: number, email: string): void {
	db.execute("UPDATE user SET email = ?, email_verified = 1 WHERE id = ?", [email, userId]);
}

export function setUserAsEmailVerifiedIfEmailMatches(userId: number, email: string): boolean {
	const result = db.execute("UPDATE user SET email_verified = 1 WHERE id = ? AND email = ?", [userId, email]);
	return result.changes > 0;
}

export function getUserPasswordHash(userId: number): string {
	const row = db.queryOne("SELECT password_hash FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	return row.string(0);
}

export function getUserRecoverCode(userId: number): string {
	const row = db.queryOne("SELECT recovery_code FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	return decryptToString(row.bytes(0));
}

export function getUserTOTPKey(userId: number): Uint8Array | null {
	const row = db.queryOne("SELECT totp_key FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	const encrypted = row.bytesNullable(0);
	if (encrypted === null) {
		return null;
	}
	return decrypt(encrypted);
}

export function updateUserTOTPKey(userId: number, key: Uint8Array): void {
	const encrypted = encrypt(key);
	db.execute("UPDATE user SET totp_key = ? WHERE id = ?", [encrypted, userId]);
}

export function resetUserRecoveryCode(userId: number): string {
	const recoveryCode = generateRandomRecoveryCode();
	const encrypted = encryptString(recoveryCode);
	db.execute("UPDATE user SET recovery_code = ? WHERE id = ?", [encrypted, userId]);
	return recoveryCode;
}

export function getUserFromEmail(email: string): User | null {
	const row = db.queryOne(
		"SELECT id, email, username, email_verified, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE email = ?",
		[email]
	);
	if (row === null) {
		return null;
	}
	const user: User = {
		id: row.number(0),
		email: row.string(1),
		username: row.string(2),
		emailVerified: Boolean(row.number(3)),
		registered2FA: Boolean(row.number(4))
	};
	return user;
}

export interface User {
	id: number;
	email: string;
	username: string;
	emailVerified: boolean;
	registered2FA: boolean;
}
