import type { APIContext } from "astro";
import {
	createEmailVerificationRequest,
	deleteUserEmailVerificationRequest,
	getUserEmailVerificationRequest,
	sendVerificationEmail
} from "@lib/email";
import { verifyExpirationDate } from "@lib/utils";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifyUserEmail } from "@lib/user";
import { invalidateUserPasswordResetSession } from "@lib/password";
import { FixedRefillTokenBucket } from "@lib/rate-limit";

const bucket = new FixedRefillTokenBucket<number>(5, 60 * 30);

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.user === null) {
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
	let verificationRequest = getUserEmailVerificationRequest(context.locals.user.id);
	if (verificationRequest === null) {
		return new Response("Invalid request", {
			status: 400
		});
	}
	if (!bucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!verifyExpirationDate(verificationRequest.expiresAt)) {
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
	invalidateUserPasswordResetSession(context.locals.user.id);
	verifyUserEmail(context.locals.user.id, verificationRequest.email);
	return new Response();
}
