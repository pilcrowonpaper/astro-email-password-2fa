import { base32 } from "@oslojs/encoding";
import { db } from "./db";

export function verifyUsernameInput(username: string): boolean {
	return username.length > 3 && username.length < 32 && username.trim() === username;
}

export function createUser(email: string, username: string, passwordHash: string): User {
	const createdAt = new Date();
	const row = db.queryOne(
		"INSERT INTO user (email, username, password_hash, created_at, recovery_code) VALUES (?, ?, ?, ?, ?) RETURNING user.id",
		[email, username, passwordHash, Math.floor(createdAt.getTime() / 1000), generateRandomRecoveryCode()]
	);
	if (row === null) {
		throw new Error("Unexpected error");
	}
	const user: User = {
		id: row.number(0),
		username,
		email,
		emailVerified: false,
		createdAt,
		registeredTOTP: false
	};
	return user;
}

export function getUser(userId: number): User {
	const row = db.queryOne(
		"SELECT id, email, username, email_verified, created_at, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE id = ?",
		[userId]
	);
	if (row === null) {
		throw new Error("");
	}
	const user: User = {
		id: row.number(0),
		email: row.string(1),
		username: row.string(2),
		emailVerified: Boolean(row.number(3)),
		createdAt: new Date(row.number(4) * 1000),
		registeredTOTP: Boolean(row.number(5))
	};
	return user;
}

export function getUserFromEmail(email: string): User | null {
	const row = db.queryOne(
		"SELECT id, email, username, email_verified, created_at, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE email = ?",
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
		createdAt: new Date(row.number(4) * 1000),
		registeredTOTP: Boolean(row.number(5))
	};
	return user;
}

export function getUserWithPasswordHashFromEmail(email: string): UserWithPasswordHash | null {
	const row = db.queryOne(
		"SELECT id, email, username, password_hash, email_verified, created_at, IIF(totp_key IS NOT NULL, 1, 0) FROM user WHERE email = ?",
		[email]
	);
	if (row === null) {
		return null;
	}
	const user: UserWithPasswordHash = {
		id: row.number(0),
		email: row.string(1),
		username: row.string(2),
		passwordHash: row.string(3),
		emailVerified: Boolean(row.number(4)),
		createdAt: new Date(row.number(5) * 1000),
		registeredTOTP: Boolean(row.number(5))
	};
	return user;
}

export function getUserPasswordHash(userId: number): string | null {
	const row = db.queryOne("SELECT password_hash FROM user WHERE id = ?", [userId]);
	if (row === null) {
		return null;
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

export function verifyUserEmail(userId: number, email: string): void {
	db.execute("UPDATE user SET email_verified = 1, email = ? WHERE id = ?", [email, userId]);
}

export function updateUserPasswordWithEmailVerification(userId: number, email: string, passwordHash: string): void {
	db.execute("UPDATE user SET password_hash = ? WHERE id = ? AND email = ?", [passwordHash, userId, email]);
}

export function updateUserPassword(userId: number, passwordHash: string): void {
	db.execute("UPDATE user SET password_hash = ? WHERE id = ?", [passwordHash, userId]);
}

export function updateUserTOTPKey(userId: number, key: Uint8Array | null): void {
	db.execute("UPDATE user SET totp_key = ? WHERE id = ?", [key, userId]);
}

export function resetUserRecoveryCode(userId: number): string {
	const code = generateRandomRecoveryCode();
	db.execute("UPDATE user SET recovery_code = ? WHERE id = ?", [code, userId]);
	return code;
}

function generateRandomRecoveryCode(): string {
	const recoveryCodeBytes = new Uint8Array(10);
	crypto.getRandomValues(recoveryCodeBytes);
	const recoveryCode = base32.encode(recoveryCodeBytes);
	return recoveryCode;
}

export interface User {
	id: number;
	email: string;
	username: string;
	emailVerified: boolean;
	createdAt: Date;
	registeredTOTP: boolean;
}

export interface UserWithPasswordHash extends User {
	passwordHash: string;
}
