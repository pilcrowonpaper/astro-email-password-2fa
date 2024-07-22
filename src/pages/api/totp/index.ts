import { verifyTOTP } from "@oslojs/otp";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { verifySession2FA } from "@lib/session";

import type { APIContext } from "astro";
import { totpBucket } from "@lib/2fa";
import { getUserTOTPKey } from "@lib/user";

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
	if (context.locals.session.twoFactorVerified) {
		return new Response("Already verified", {
			status: 401
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
	if (!totpBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!context.locals.user.registeredTOTP) {
		return new Response("Please set up two-factor authentication.", {
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
	verifySession2FA(context.locals.session.id);
	return new Response();
}
