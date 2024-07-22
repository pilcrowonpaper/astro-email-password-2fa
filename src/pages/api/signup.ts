import { ObjectParser } from "@pilcrowjs/object-parser";
import { hashPassword, verifyPasswordStrength } from "@lib/password";
import { createSession, lucia } from "@lib/session";
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

const bucket = new ConstantRefillTokenBucket(10, 10);

export async function POST(context: APIContext): Promise<Response> {
	if (import.meta.env.PROD) {
		const clientIP = context.request.headers.get("X-Forwarded-For");
		if (clientIP === null || !bucket.check(clientIP, 1)) {
			return new Response("Too many requests", {
				status: 429
			});
		}
	}
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let email: string, username: string, password: string;
	try {
		email = parser.getString("email");
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
	const strongPassword = await verifyPasswordStrength(password);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	const passwordHash = await hashPassword(password);
	const user = createUser(email, username, passwordHash);
	const emailVerificationRequest = createEmailVerificationRequest(user.id, user.email);
	sendVerificationEmail(emailVerificationRequest.email, emailVerificationRequest.code);
	const sessionFlags: SessionFlags = {
		twoFactorVerified: false
	};
	const session = createSession(user.id, sessionFlags);
	const sessionCookie = lucia.createSessionCookie(session.id, session.expiresAt);
	context.cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.npmCookieOptions());
	return new Response();
}
