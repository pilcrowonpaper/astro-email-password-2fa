import { invalidateSession, deleteSessionCookie } from "@lib/session";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null) {
		return new Response(null, {
			status: 401
		});
	}
	invalidateSession(context.locals.session.id);
	deleteSessionCookie(context);
	return new Response();
}
