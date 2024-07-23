import { invalidateUserPasswordResetSession, validatePasswordResetSessionRequest } from "@lib/password";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordStrength } from "@lib/password";
import { createSession, lucia } from "@lib/session";
import { getUser, updateUserPasswordWithEmailVerification } from "@lib/user";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/session";

export async function POST(context: APIContext): Promise<Response> {
	const passwordResetSession = validatePasswordResetSessionRequest(context);
	if (passwordResetSession === null || !passwordResetSession.emailVerified) {
		return new Response(null, {
			status: 401
		});
	}
	const user = getUser(passwordResetSession.userId);
	if (user === null) {
		return new Response(null, {
			status: 500
		});
	}
	if (user.registeredTOTP && !passwordResetSession.twoFactorVerified) {
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
	if (password.length < 8 || password.length > 255) {
		return new Response("Invalid password", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(password);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	invalidateUserPasswordResetSession(passwordResetSession.userId);
	await updateUserPasswordWithEmailVerification(passwordResetSession.userId, passwordResetSession.email, password);

	const sessionFlags: SessionFlags = {
		twoFactorVerified: true
	};
	const session = createSession(passwordResetSession.userId, sessionFlags);

	const sessionCookie = lucia.createSessionCookie(session.id, session.expiresAt);

	context.cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.npmCookieOptions());
	context.cookies.set("password_reset_session", "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
	return new Response();
}
