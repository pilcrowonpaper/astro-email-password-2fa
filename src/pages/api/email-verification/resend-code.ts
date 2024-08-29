import {
	createEmailVerificationRequest,
	getUserEmailVerificationRequestFromRequest,
	sendVerificationEmailBucket,
	sendVerificationEmail,
	setEmailVerificationRequestCookie
} from "@lib/server/email-verification";

import type { APIContext } from "astro";

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
	if (!sendVerificationEmailBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	verificationRequest = createEmailVerificationRequest(verificationRequest.userId, verificationRequest.email);
	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	setEmailVerificationRequestCookie(context, verificationRequest);
	return new Response(null, { status: 204 });
}
