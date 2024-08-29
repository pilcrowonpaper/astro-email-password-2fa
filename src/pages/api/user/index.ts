import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordStrength } from "@lib/server/password";
import { createSession, setSessionCookie } from "@lib/server/session";
import { createUser, verifyUsernameInput } from "@lib/server/user";
import { checkEmailAvailability, verifyEmailInput } from "@lib/server/email";
import {
	createEmailVerificationRequest,
	sendVerificationEmail,
	setEmailVerificationRequestCookie
} from "@lib/server/email-verification";
import { ConstantRefillTokenBucket } from "@lib/server/rate-limit";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/server/session";

const bucket = new ConstantRefillTokenBucket(10, 5);

export async function POST(context: APIContext): Promise<Response> {
	const clientIP = context.request.headers.get("X-Forwarded-For");
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string, username: string, password: string;
	try {
		email = parser.getString("email").toLowerCase();
		username = parser.getString("username");
		password = parser.getString("password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (email === "" || password === "" || username === "") {
		return new Response("Please enter your username, email, and password", {
			status: 400
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Invalid email", {
			status: 400
		});
	}
	const emailAvailable = checkEmailAvailability(email);
	if (!emailAvailable) {
		return new Response("Email is already used", {
			status: 400
		});
	}
	if (!verifyUsernameInput(username)) {
		return new Response("Invalid username", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(password);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	if (clientIP !== null && !bucket.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const user = await createUser(email, username, password);
	const emailVerificationRequest = createEmailVerificationRequest(user.id, user.email);
	sendVerificationEmail(emailVerificationRequest.email, emailVerificationRequest.code);
	setEmailVerificationRequestCookie(context, emailVerificationRequest);

	const sessionFlags: SessionFlags = {
		twoFactorVerified: false
	};
	const session = createSession(user.id, sessionFlags);
	setSessionCookie(context, session);
	return new Response(null, { status: 204 });
}
