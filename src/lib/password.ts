import { hash, verify } from "@node-rs/argon2";
import { sha1 } from "@oslojs/crypto/sha1";
import { encodeHex } from "@oslojs/encoding";
import { generateSessionId } from "lucia";
import { db } from "./db";
import { generateRandomOTP, verifyExpirationDate } from "./utils";

import type { APIContext } from "astro";

export async function hashPassword(password: string): Promise<string> {
	return await hash(password, {
		memoryCost: 19456,
		timeCost: 2,
		outputLen: 32,
		parallelism: 1
	});
}

export async function verifyPasswordHash(hash: string, password: string): Promise<boolean> {
	return await verify(hash, password);
}

export async function verifyPasswordStrength(password: string): Promise<boolean> {
	const hash = encodeHex(sha1(new TextEncoder().encode(password)));
	const hashPrefix = hash.slice(0, 5);
	const response = await fetch(`https://api.pwnedpasswords.com/range/${hashPrefix}`);
	const data = await response.text();
	const items = data.split("\n");
	for (const item of items) {
		const hashSuffix = item.slice(0, 35).toLowerCase();
		if (hash === hashPrefix + hashSuffix) {
			return false;
		}
	}
	return true;
}

export function createPasswordResetSession(userId: number, email: string): PasswordResetSession {
	const session: PasswordResetSession = {
		id: generateSessionId(),
		userId,
		email,
		expiresAt: new Date(Date.now() + 1000 * 60 * 10),
		code: generateRandomOTP(),
		emailVerified: false,
		twoFactorVerified: false
	};
	db.execute("INSERT INTO password_reset_session (id, user_id, email, code, expires_at) VALUES (?, ?, ?, ?, ?)", [
		session.id,
		session.userId,
		session.email,
		session.code,
		Math.floor(session.expiresAt.getTime() / 1000)
	]);
	return session;
}

export function invalidateUserPasswordResetSessions(userId: number) {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export function validatePasswordResetSessionRequest(context: APIContext): PasswordResetSession | null {
	const sessionId = context.cookies.get("password_reset_session")?.value ?? null;
	if (sessionId === null) {
		return null;
	}
	const session = getPasswordResetSession(sessionId);
	if (session === null) {
		return null;
	}
	if (!verifyExpirationDate(session.expiresAt)) {
		invalidateUserPasswordResetSession(session.userId);
		setBlankPasswordResetSessionCookie(context);
		return null;
	}
	return session;
}

export function getPasswordResetSession(sessionId: string): PasswordResetSession | null {
	const row = db.queryOne(
		"SELECT id, user_id, email, code, expires_at, email_verified, two_factor_verified FROM password_reset_session WHERE id = ?",
		[sessionId]
	);
	if (row === null) {
		return null;
	}
	const session: PasswordResetSession = {
		id: row.string(0),
		userId: row.number(1),
		email: row.string(2),
		code: row.string(3),
		expiresAt: new Date(row.number(4) * 1000),
		emailVerified: Boolean(row.number(5)),
		twoFactorVerified: Boolean(row.number(6))
	};
	return session;
}

export function setBlankPasswordResetSessionCookie(context: APIContext): void {
	context.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function invalidateUserPasswordResetSession(userId: number): void {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export function verifyPasswordResetSessionEmail(sessionId: string, email: string): boolean {
	const result = db.execute("UPDATE password_reset_session SET email_verified = 1 WHERE id = ? AND email = ?", [
		sessionId,
		email
	]);
	return result.changes > 0;
}

export function verifyPasswordResetSession2FA(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export function sendPasswordResetEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}

interface PasswordResetSession {
	id: string;
	userId: number;
	email: string;
	code: string;
	expiresAt: Date;
	emailVerified: boolean;
	twoFactorVerified: boolean;
}
