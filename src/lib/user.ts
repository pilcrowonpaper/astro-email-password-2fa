import { encodeBase32 } from "@oslojs/encoding";
import { db } from "./db";
import { hashPassword } from "./password";

export function verifyUsernameInput(username: string): boolean {
	return username.length > 3 && username.length < 32 && username.trim() === username;
}

export async function createUser(email: string, username: string, password: string): Promise<User> {
	const passwordHash = await hashPassword(password);
	const recoveryCode = generateRandomRecoveryCode();
	const row = db.queryOne(
		"INSERT INTO user (email, username, password_hash, recovery_code) VALUES (?, ?, ?, ?) RETURNING user.id",
		[email, username, passwordHash, recoveryCode]
	);
	if (row === null) {
		throw new Error("Unexpected error");
	}
	const user: User = {
		id: row.number(0),
		username,
		email,
		emailVerified: false,
		registeredTOTP: false
	};
	return user;
}

export function getUser(userId: number): User | null {
	const row = db.queryOne(
		"SELECT id, email, username, email_verified, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE id = ?",
		[userId]
	);
	if (row === null) {
		return null;
	}
	const user: User = {
		id: row.number(0),
		email: row.string(1),
		username: row.string(2),
		emailVerified: Boolean(row.number(3)),
		registeredTOTP: Boolean(row.number(4))
	};
	return user;
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
	return row.string(0);
}

export function getUserTOTPKey(userId: number): Uint8Array | null {
	const row = db.queryOne("SELECT totp_key FROM user WHERE id = ?", [userId]);
	if (row === null) {
		throw new Error("Invalid user ID");
	}
	return row.bytesNullable(0);
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
		registeredTOTP: Boolean(row.number(4))
	};
	return user;
}

export function verifyUserRecoveryCode(userId: number, recoveryCode: string): boolean {
	const newRecoveryCode = generateRandomRecoveryCode();
	try {
		db.execute("BEGIN TRANSACTION", []);
		const result = db.execute("UPDATE user SET recovery_code = ?, totp_key = NULL WHERE id = ? AND recovery_code = ?", [
			newRecoveryCode,
			userId,
			recoveryCode
		]);
		if (result.changes < 1) {
			db.execute("COMMIT", []);
			return false;
		}
		db.execute("UPDATE session SET two_factor_verified = 0 WHERE user_id = ?", [userId]);
		db.execute("COMMIT", []);
		return true;
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export function resetUserRecoveryCode(sessionId: string, userId: number): string {
	const recoveryCode = generateRandomRecoveryCode();
	try {
		db.execute("BEGIN TRANSACTION", []);
		db.execute("UPDATE user SET recovery_code = ?, totp_key = NULL WHERE id = ?", [recoveryCode, userId]);
		db.execute("DELETE FROM session WHERE id != ? AND user_id = ?", [sessionId, userId]);
		db.execute("COMMIT", []);
		return recoveryCode;
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export function verifyUserEmail(userId: number, email: string): void {
	db.execute("UPDATE user SET email_verified = 1, email = ? WHERE id = ?", [email, userId]);
}

export async function updateUserPasswordWithEmailVerification(
	userId: number,
	email: string,
	password: string
): Promise<void> {
	const passwordHash = await hashPassword(password);
	try {
		db.execute("BEGIN TRANSACTION", []);
		const result = db.execute("UPDATE user SET password_hash = ? WHERE id = ? AND email = ?", [
			passwordHash,
			userId,
			email
		]);
		if (result.changes < 1) {
			db.execute("COMMIT", []);
			throw new Error("Invalid user ID");
		}
		db.execute("DELETE FROM session WHERE user_id = ?", [userId]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export async function updateUserPassword(sessionId: string, userId: number, password: string): Promise<void> {
	const passwordHash = await hashPassword(password);
	try {
		db.execute("BEGIN TRANSACTION", []);
		db.execute("UPDATE user SET password_hash = ? WHERE id = ?", [passwordHash, userId]);
		db.execute("DELETE FROM session WHERE id != ? AND user_id = ?", [sessionId, userId]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

export function updateUserTOTPKey(sessionId: string, userId: number, key: Uint8Array): void {
	try {
		db.execute("BEGIN TRANSACTION", []);
		db.execute("UPDATE user SET totp_key = ? WHERE id = ?", [key, userId]);
		db.execute("DELETE FROM session WHERE id != ? AND user_id = ?", [sessionId, userId]);
		db.execute("UPDATE session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
}

function generateRandomRecoveryCode(): string {
	const recoveryCodeBytes = new Uint8Array(10);
	crypto.getRandomValues(recoveryCodeBytes);
	const recoveryCode = encodeBase32(recoveryCodeBytes);
	return recoveryCode;
}

export interface User {
	id: number;
	email: string;
	username: string;
	emailVerified: boolean;
	registeredTOTP: boolean;
}
