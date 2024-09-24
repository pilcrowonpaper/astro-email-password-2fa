import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordHash } from "@lib/server/password";
import { createSession, generateSessionToken, setSessionTokenCookie } from "@lib/server/session";
import { verifyEmailInput } from "@lib/server/email";
import { Throttler } from "@lib/server/rate-limit";
import { getUserFromEmail, getUserPasswordHash } from "@lib/server/user";
import { invalidateSession, deleteSessionTokenCookie } from "@lib/server/session";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

const throttler = new Throttler<number>([0, 1, 2, 4, 8, 16, 30, 60, 180, 300]);

export async function POST(context: APIContext): Promise<Response> {
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string, password: string;
	try {
		email = parser.getString("email").toLowerCase();
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (email === "" || password === "") {
		return new Response("Please enter your email and password.", {
			status: 400
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Invalid email", {
			status: 400
		});
	}
	const user = getUserFromEmail(email);
	if (user === null) {
		return new Response("Account does not exist", {
			status: 400
		});
	}
	if (!throttler.check(user.id)) {
		return new Response("Too many request", {
			status: 429
		});
	}
	const passwordHash = getUserPasswordHash(user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		throttler.increment(user.id);
		return new Response("Invalid password", {
			status: 400
		});
	}
	throttler.reset(user.id);
	const sessionFlags: SessionFlags = {
		twoFactorVerified: false
	};
	const sessionToken = generateSessionToken();
	const session = createSession(sessionToken, user.id, sessionFlags);
	setSessionTokenCookie(context, sessionToken, session.expiresAt);
	return new Response(null, { status: 201 });
}

export async function DELETE(context: APIContext): Promise<Response> {
	if (context.locals.session === null) {
		return new Response(null, {
			status: 401
		});
	}
	invalidateSession(context.locals.session.id);
	deleteSessionTokenCookie(context);
	return new Response(null, { status: 204 });
}
