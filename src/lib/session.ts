import { db } from "./db";
import { generateSessionId, Lucia } from "lucia";

import type { DatabaseAdapter, LuciaSession, SessionAndUser } from "lucia";
import type { User } from "./user";

const adapter: DatabaseAdapter<Session, User> = {
	getSessionAndUser: async (sessionId: string): Promise<SessionAndUser<Session, User>> => {
		const row = db.queryOne(
			`
SELECT session.id, session.user_id, session.expires_at, session.authenticated_at, session.two_factor_verified, user.id, user.email, user.username, user.email_verified, user.created_at, IIF(user.totp_key IS NOT NULL, 1, 0) FROM session
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
			authenticatedAt: new Date(row.number(3) * 1000),
			twoFactorVerified: Boolean(row.number(4))
		};
		const user: User = {
			id: row.number(5),
			email: row.string(6),
			username: row.string(7),
			emailVerified: Boolean(row.number(8)),
			createdAt: new Date(row.number(9) * 1000),
			registeredTOTP: Boolean(row.number(10))
		};
		return { session, user };
	},
	deleteSession: async (sessionId: string): Promise<void> => {
		db.execute("DELETE FROM session WHERE session.id = ?", [sessionId]);
	},
	updateSessionExpiration: async (sessionId: string, expiresAt: Date): Promise<void> => {
		db.execute("UPDATE session SET expires_at = ? WHERE session.id = ?", [
			Math.floor(expiresAt.getTime() / 1000),
			sessionId
		]);
	}
};

export const lucia = new Lucia(adapter, {
	secureCookies: !import.meta.env.DEV
});

export function createSession(userId: number, flags: SessionFlags): Session {
	const session: Session = {
		id: generateSessionId(),
		userId,
		expiresAt: lucia.getNewSessionExpiration(),
		authenticatedAt: new Date(),
		twoFactorVerified: flags.twoFactorVerified
	};
	db.execute(
		"INSERT INTO session (id, user_id, expires_at, authenticated_at, two_factor_verified) VALUES (?, ?, ?, ?, ?)",
		[
			session.id,
			session.userId,
			Math.floor(session.expiresAt.getTime() / 1000),
			Math.floor(session.authenticatedAt.getTime() / 1000),
			Number(session.twoFactorVerified)
		]
	);
	return session;
}

export function verifySession2FA(sessionId: string): void {
	db.execute("UPDATE session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export interface SessionFlags {
	twoFactorVerified: boolean;
}

export interface Session extends LuciaSession, SessionFlags {
	userId: number;
	authenticatedAt: Date;
}
