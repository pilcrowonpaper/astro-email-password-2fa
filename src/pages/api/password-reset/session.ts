import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyEmailInput } from "@lib/server/email";
import { getUserFromEmail } from "@lib/server/user";
import {
	createPasswordResetSession,
	invalidateUserPasswordResetSessions,
	sendPasswordResetEmail,
	setPasswordResetSessionCookie
} from "@lib/server/password-reset";
import { ConstantRefillTokenBucket } from "@lib/server/rate-limit";

import type { APIContext } from "astro";

const bucket = new ConstantRefillTokenBucket<string>(3, 30);

export async function POST(context: APIContext): Promise<Response> {
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string;
	try {
		email = parser.getString("email").toLowerCase();
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
	setPasswordResetSessionCookie(context, session);
	return new Response();
}
