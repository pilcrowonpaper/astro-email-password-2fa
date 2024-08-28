import { decodeBase64 } from "@oslojs/encoding";
import { verifyTOTP } from "@oslojs/otp";
import { updateUserTOTPKey } from "@lib/server/user";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { setSessionAs2FAVerified } from "@lib/server/session";
import { totpBucket } from "@lib/server/2fa";

import type { APIContext } from "astro";

export async function PATCH(context: APIContext): Promise<Response> {
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
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}
	if (!totpBucket.check(context.locals.user.id, 2)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let encodedKey: string, code: string;
	try {
		encodedKey = parser.getString("key");
		code = parser.getString("code");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	if (code === "") {
		return new Response("Please enter your code", {
			status: 401
		});
	}
	if (encodedKey.length !== 28) {
		return new Response("Invalid key", {
			status: 400
		});
	}
	const key = decodeBase64(encodedKey);
	if (key.byteLength !== 20) {
		return new Response("Invalid key", {
			status: 400
		});
	}
	if (!verifyTOTP(key, 30, 6, code)) {
		return new Response("Invalid code", {
			status: 400
		});
	}
	// TODO: Should a new recovery code be generated?
	updateUserTOTPKey(context.locals.session.userId, key);
	setSessionAs2FAVerified(context.locals.session.id);
	return new Response(null, { status: 201 });
}
