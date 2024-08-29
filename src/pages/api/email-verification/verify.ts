import {
	createEmailVerificationRequest,
	deleteEmailVerificationRequestCookie,
	deleteUserEmailVerificationRequest,
	getUserEmailVerificationRequestFromRequest,
	sendVerificationEmail
} from "@lib/server/email-verification";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { updateUserEmailAndSetEmailAsVerified } from "@lib/server/user";
import { invalidateUserPasswordResetSessions } from "@lib/server/password-reset";
import { FixedRefillTokenBucket } from "@lib/server/rate-limit";

import type { APIContext } from "astro";

const bucket = new FixedRefillTokenBucket<number>(5, 60 * 30);

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}

	let verificationRequest = getUserEmailVerificationRequestFromRequest(context);
	if (verificationRequest === null) {
		return new Response(null, {
			status: 401
		});
	}
	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let code: string;
	try {
		code = parser.getString("code");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (code === "") {
		return new Response("Enter your code", {
			status: 400
		});
	}
	if (!bucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (Date.now() >= verificationRequest.expiresAt.getTime()) {
		verificationRequest = createEmailVerificationRequest(verificationRequest.userId, verificationRequest.email);
		sendVerificationEmail(verificationRequest.email, verificationRequest.code);
		return new Response("The verification code was expired. We sent another code to your inbox.", {
			status: 400
		});
	}
	if (verificationRequest.code !== code) {
		return new Response("Incorrect code.", {
			status: 400
		});
	}
	deleteUserEmailVerificationRequest(context.locals.user.id);
	invalidateUserPasswordResetSessions(context.locals.user.id);
	updateUserEmailAndSetEmailAsVerified(context.locals.user.id, verificationRequest.email);
	deleteEmailVerificationRequestCookie(context);
	return new Response(null, { status: 204 });
}
