import { db } from "./db";
import { encodeBase32 } from "@oslojs/encoding";

import type { User } from "./user";
import type { APIContext } from "astro";

export function validateSession(sessionId: string): SessionValidationResult {
	const row = db.queryOne(
		`
SELECT session.id, session.user_id, session.expires_at, session.two_factor_verified, user.id, user.email, user.username, user.email_verified, user.created_at, IIF(user.totp_key IS NOT NULL, 1, 0) FROM session
INNER JOIN user ON session.user_id = user.id
WHERE session.id = ?
`,
		[sessionId]
	);

	if (row === null) {
		return { session: null, user: null };
	}
	const session: Session = {
		id: row.string(0),
		userId: row.number(1),
		expiresAt: new Date(row.number(2) * 1000),
		twoFactorVerified: Boolean(row.number(3))
	};
	const user: User = {
		id: row.number(4),
		email: row.string(5),
		username: row.string(6),
		emailVerified: Boolean(row.number(7)),
		createdAt: new Date(row.number(8) * 1000),
		registeredTOTP: Boolean(row.number(9))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM session WHERE id = ?", [sessionId]);
		return { session: null, user: null };
	}
	if (Date.now() >= session.expiresAt.getTime() - 1000 * 60 * 60 * 24 * 15) {
		session.expiresAt = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30);
		db.execute("UPDATE session SET expires_at = ? WHERE session.id = ?", [
			Math.floor(session.expiresAt.getTime() / 1000),
			sessionId
		]);
	}
	return { session, user };
}

export async function invalidateSession(sessionId: string): Promise<void> {
	db.execute("DELETE FROM session WHERE id = ?", [sessionId]);
}

export function validateRequest(context: APIContext): SessionValidationResult {
	const sessionId = context.cookies.get("session")?.value ?? null;
	if (sessionId === null) {
		return {
			session: null,
			user: null
		};
	}
	const result = validateSession(sessionId);
	if (result.session !== null) {
		setSessionCookie(context, result.session);
	} else {
		deleteSessionCookie(context);
	}
	return result;
}

export function setSessionCookie(context: APIContext, session: Session): void {
	context.cookies.set("session", session.id, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: session.expiresAt
	});
}

export function deleteSessionCookie(context: APIContext): void {
	context.cookies.set("session", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export function createSession(userId: number, flags: SessionFlags): Session {
	const idBytes = new Uint8Array(20);
	crypto.getRandomValues(idBytes);
	const id = encodeBase32(idBytes).toLowerCase();

	const session: Session = {
		id,
		userId,
		expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30),
		twoFactorVerified: flags.twoFactorVerified
	};
	db.execute("INSERT INTO session (id, user_id, expires_at, two_factor_verified) VALUES (?, ?, ?, ?)", [
		session.id,
		session.userId,
		Math.floor(session.expiresAt.getTime() / 1000),
		Number(session.twoFactorVerified)
	]);
	return session;
}

export function verifySession2FA(sessionId: string): void {
	db.execute("UPDATE session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export interface SessionFlags {
	twoFactorVerified: boolean;
}

export interface Session extends SessionFlags {
	id: string;
	expiresAt: Date;
	userId: number;
}

type SessionValidationResult = { session: Session; user: User } | { session: null; user: null };
