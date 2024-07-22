import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserRecoverCode, resetUserRecoveryCode, updateUserTOTPKey } from "@lib/user";
import { unverifySession2FA } from "@lib/session";
import { recoveryCodeBucket } from "@lib/2fa";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
    if (!context.locals.user.registeredTOTP) {
		return new Response(null, {
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
		return new Response("Please enter your code", {
			status: 401
		});
	}
	if (!recoveryCodeBucket.check(context.locals.user.id, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const recoveryCode = getUserRecoverCode(context.locals.user.id);
	if (code !== recoveryCode) {
		return new Response("Invalid recovery code", {
			status: 400
		});
	}
	resetUserRecoveryCode(context.locals.user.id);
	updateUserTOTPKey(context.locals.user.id, null);
	unverifySession2FA(context.locals.session.id);
	recoveryCodeBucket.reset(context.locals.user.id);
	return new Response();
}
