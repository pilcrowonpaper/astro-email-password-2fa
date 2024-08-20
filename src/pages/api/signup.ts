import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyPasswordStrength } from "@lib/password";
import { createSession, setSessionCookie } from "@lib/session";
import { createUser, verifyUsernameInput } from "@lib/user";
import {
	createEmailVerificationRequest,
	sendVerificationEmail,
	checkEmailAvailability,
	verifyEmailInput
} from "@lib/email";
import { ConstantRefillTokenBucket } from "@lib/rate-limit";

import type { APIContext } from "astro";
import type { SessionFlags } from "@lib/session";

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
	if (password.length < 8 || password.length > 255) {
		return new Response("Invalid password", {
			status: 400
		});
	}
	if (clientIP !== null && !bucket.check(clientIP, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const strongPassword = await verifyPasswordStrength(password);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	const user = await createUser(email, username, password);
	const emailVerificationRequest = createEmailVerificationRequest(user.id, user.email);
	sendVerificationEmail(emailVerificationRequest.email, emailVerificationRequest.code);
	const sessionFlags: SessionFlags = {
		twoFactorVerified: false
	};
	const session = createSession(user.id, sessionFlags);
	setSessionCookie(context, session);
	return new Response();
}
