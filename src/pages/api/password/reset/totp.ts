import { verifyTOTP } from "@oslojs/otp";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserTOTPKey } from "@lib/user";
import { validatePasswordResetSessionRequest, verifyPasswordResetSession2FA } from "@lib/password";
import { totpBucket } from "@lib/2fa";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const session = validatePasswordResetSessionRequest(context);
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
	const totpKey = getUserTOTPKey(session.userId);
	if (totpKey === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (!totpBucket.check(session.userId, 1)) {
		return new Response("Too many requests", {
			status: 429
		});
	}
	if (!verifyTOTP(totpKey, 30, 6, code)) {
		return new Response("Invalid code", {
			status: 400
		});
	}
	totpBucket.reset(session.userId);
	verifyPasswordResetSession2FA(session.id);
	return new Response();
}
