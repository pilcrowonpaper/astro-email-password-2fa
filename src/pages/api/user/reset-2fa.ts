import { ObjectParser } from "@pilcrowjs/object-parser";
import { recoveryCodeBucket, resetUser2FAWithRecoveryCode } from "@lib/server/2fa";

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
	const valid = resetUser2FAWithRecoveryCode(context.locals.user.id, code);
	if (!valid) {
		return new Response("Invalid recovery code", {
			status: 400
		});
	}
	recoveryCodeBucket.reset(context.locals.user.id);
	return new Response(null, {
		status: 201
	});
}
