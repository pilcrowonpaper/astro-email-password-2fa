import { ObjectParser } from "@pilcrowjs/object-parser";
import { resetUser2FAWithRecoveryCode } from "@lib/server/2fa";
import { validatePasswordResetSessionRequest } from "@lib/server/password-reset";
import { recoveryCodeBucket } from "@lib/server/2fa";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const { session } = validatePasswordResetSessionRequest(context);
	if (session === null || !session.emailVerified) {
		return new Response(null, {
			status: 401
		});
	}
	if (session.twoFactorVerified) {
		return new Response("Already verified", {
			status: 400
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
	if (!recoveryCodeBucket.check(session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	const valid = resetUser2FAWithRecoveryCode(session.userId, code);
	if (!valid) {
		return new Response("Invalid code", {
			status: 400
		});
	}
	recoveryCodeBucket.reset(session.userId);
	return new Response();
}
