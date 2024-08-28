import { db } from "./db";
import { encodeBase32 } from "@oslojs/encoding";
import { generateRandomOTP } from "./utils";

import type { APIContext } from "astro";
import type { User } from "./user";

export function createPasswordResetSession(userId: number, email: string): PasswordResetSession {
	const idBytes = new Uint8Array(20);
	crypto.getRandomValues(idBytes);
	const id = encodeBase32(idBytes).toLowerCase();

	const session: PasswordResetSession = {
		id,
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

export function validatePasswordResetSession(sessionId: string): PasswordResetSessionValidationResult {
	const row = db.queryOne(
		`SELECT password_reset_session.id, password_reset_session.user_id, password_reset_session.email, password_reset_session.code, password_reset_session.expires_at, password_reset_session.email_verified, password_reset_session.two_factor_verified,
user.id, user.email, user.username, user.email_verified
FROM password_reset_session INNER JOIN user ON user.id = password_reset_session.user_id
WHERE password_reset_session.id = ?`,
		[sessionId]
	);
	if (row === null) {
		return { session: null, user: null };
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
	const user: User = {
		id: row.number(7),
		email: row.string(8),
		username: row.string(9),
		emailVerified: Boolean(row.number(10)),
		registered2FA: Boolean(row.number(11))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM password_reset_session WHERE id = ?", [session.id]);
		return { session: null, user: null };
	}
	return { session, user };
}

export function setPasswordResetSessionAsEmailVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET email_verified = 1 WHERE id = ?", [sessionId]);
}

export function setPasswordResetSessionAs2FAVerified(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export function invalidateUserPasswordResetSessions(userId: number): void {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export function validatePasswordResetSessionRequest(context: APIContext): PasswordResetSessionValidationResult {
	const sessionId = context.cookies.get("password_reset_session")?.value ?? null;
	if (sessionId === null) {
		return { session: null, user: null };
	}
	const result = validatePasswordResetSession(sessionId);
	if (result.session === null) {
		deletePasswordResetSessionCookie(context);
	}
	return result;
}

export function setPasswordResetSessionCookie(context: APIContext, session: PasswordResetSession): void {
	context.cookies.set("password_reset_session", session.id, {
		expires: session.expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deletePasswordResetSessionCookie(context: APIContext): void {
	context.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function sendPasswordResetEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}

export interface PasswordResetSession {
	id: string;
	userId: number;
	email: string;
	expiresAt: Date;
	code: string;
	emailVerified: boolean;
	twoFactorVerified: boolean;
}

export type PasswordResetSessionValidationResult =
	| { session: PasswordResetSession; user: User }
	| { session: null; user: null };
