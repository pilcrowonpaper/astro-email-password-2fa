import { ObjectParser } from "@pilcrowjs/object-parser";
import {
	createEmailVerificationRequest,
	sendVerificationEmailBucket,
	sendVerificationEmail,
	setEmailVerificationRequestCookie
} from "@lib/server/email-verification";
import { verifyEmailInput, checkEmailAvailability } from "@lib/server/email";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
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
	if (email === "") {
		return new Response("Please enter your email", {
			status: 401
		});
	}
	if (!verifyEmailInput(email)) {
		return new Response("Please enter a valid email", {
			status: 401
		});
	}
	const emailAvailable = checkEmailAvailability(email);
	if (!emailAvailable) {
		return new Response("This email is already used", {
			status: 401
		});
	}
	if (!sendVerificationEmailBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const verificationRequest = createEmailVerificationRequest(context.locals.user.id, email);
	sendVerificationEmail(verificationRequest.email, verificationRequest.code);
	setEmailVerificationRequestCookie(context, verificationRequest);
	return new Response(null, { status: 201 });
}
