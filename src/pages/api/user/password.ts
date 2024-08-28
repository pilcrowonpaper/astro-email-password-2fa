import { ObjectParser } from "@pilcrowjs/object-parser";
import { getUserPasswordHash, updateUserPassword } from "@lib/server/user";
import { verifyPasswordHash, verifyPasswordStrength } from "@lib/server/password";
import { invalidateUserSessionsExceptOne } from "@lib/server/session";

import type { APIContext } from "astro";

export async function PATCH(context: APIContext): Promise<Response> {
	if (context.locals.user === null || context.locals.session === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}
	const data = await context.request.json();
	const parser = new ObjectParser(data);
	let password: string, newPassword: string;
	try {
		password = parser.getString("password");
		newPassword = parser.getString("new_password");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	const strongPassword = await verifyPasswordStrength(newPassword);
	if (!strongPassword) {
		return new Response("Weak password", {
			status: 400
		});
	}
	const passwordHash = getUserPasswordHash(context.locals.user.id);
	const validPassword = await verifyPasswordHash(passwordHash, password);
	if (!validPassword) {
		return new Response("Incorrect password", {
			status: 401
		});
	}
	invalidateUserSessionsExceptOne(context.locals.user.id, context.locals.session.id);
	await updateUserPassword(context.locals.user.id, newPassword);
	return new Response(null, { status: 201 });
}
