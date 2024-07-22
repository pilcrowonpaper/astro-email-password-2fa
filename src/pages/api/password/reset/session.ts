import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyEmailInput } from "@lib/email";
import { getUserFromEmail } from "@lib/user";
import { createPasswordResetSession, invalidateUserPasswordResetSessions, sendPasswordResetEmail } from "@lib/password";
import { ConstantRefillTokenBucket } from "@lib/rate-limit";

import type { APIContext } from "astro";

const bucket = new ConstantRefillTokenBucket<string>(3, 30);

export async function POST(context: APIContext): Promise<Response> {
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string;
	try {
		email = parser.getString("email");
	} catch {
		return new Response("Invalid or missing fields", {
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
	if (!bucket.check(email, 1)) {
		return new Response("Too many requests", {
			status: 400
		});
	}
	invalidateUserPasswordResetSessions(user.id);
	const session = createPasswordResetSession(user.id, user.email);
	sendPasswordResetEmail(session.email, session.code);
	context.cookies.set("password_reset_session", session.id, {
		expires: session.expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
	return new Response();
}
