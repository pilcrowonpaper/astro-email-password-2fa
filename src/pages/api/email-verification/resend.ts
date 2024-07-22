import {
	createEmailVerificationRequest,
	getUserEmailVerificationRequest,
	sendVerificationEmailBucket,
	sendVerificationEmail
} from "@lib/email";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
	let verificationRequest = getUserEmailVerificationRequest(context.locals.user.id);
	if (verificationRequest === null) {
		return new Response("Invalid request", {
			status: 400
		});
	}
	if (!sendVerificationEmailBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	verificationRequest = createEmailVerificationRequest(verificationRequest.userId, verificationRequest.email);
	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	return new Response();
}
