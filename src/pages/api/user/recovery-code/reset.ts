import { resetUserRecoveryCode } from "@lib/server/user";

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
	if (!context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}
	const code = resetUserRecoveryCode(context.locals.session.userId);
	return new Response(code);
}
