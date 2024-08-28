import {
	deletePasswordResetSessionCookie,
	invalidateUserPasswordResetSessions,
	validatePasswordResetSessionRequest
} from "@lib/server/password-reset";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordStrength } from "@lib/server/password";
import { createSession, invalidateUserSessions, setSessionCookie } from "@lib/server/session";
import { updateUserPassword } from "@lib/server/user";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

export async function POST(context: APIContext): Promise<Response> {
	const { session: passwordResetSession, user } = validatePasswordResetSessionRequest(context);
	if (passwordResetSession === null || !passwordResetSession.emailVerified) {
		return new Response(null, {
			status: 401
		});
	}
	if (user.registered2FA && !passwordResetSession.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}
	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let password: string;
	try {
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(password);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	invalidateUserPasswordResetSessions(passwordResetSession.userId);
	invalidateUserSessions(passwordResetSession.userId);
	await updateUserPassword(passwordResetSession.userId, password);

	const sessionFlags: SessionFlags = {
		twoFactorVerified: true
	};
	const session = createSession(passwordResetSession.userId, sessionFlags);
	setSessionCookie(context, session);
	deletePasswordResetSessionCookie(context);
	return new Response(null, {
		status: 204
	});
}
