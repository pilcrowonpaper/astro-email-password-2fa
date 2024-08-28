import { verifyTOTP } from "@oslojs/otp";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { setSessionAs2FAVerified } from "@lib/server/session";
import { totpBucket } from "@lib/server/2fa";
import { getUserTOTPKey } from "@lib/server/user";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (!context.locals.user.emailVerified) {
		return new Response(null, {
			status: 401
		});
	}
	if (!context.locals.user.registered2FA) {
		return new Response("Please set up two-factor authentication.", {
			status: 400
		});
	}
	if (!totpBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const data: unknown = await context.request.json();
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
	const totpKey = getUserTOTPKey(context.locals.user.id);
	if (totpKey === null) {
		return new Response("Please set up two-factor authentication.", {
			status: 400
		});
	}
	if (!verifyTOTP(totpKey, 30, 6, code)) {
		return new Response("Invalid code", {
			status: 400
		});
	}
	totpBucket.reset(context.locals.user.id);
	setSessionAs2FAVerified(context.locals.session.id);
	return new Response(null, { status: 201 });
}
