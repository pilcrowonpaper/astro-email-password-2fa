import { defineMiddleware } from "astro:middleware";
import { lucia } from "./lib/session";
import { ConstantRefillTokenBucket } from "./lib/rate-limit";

const bucket = new ConstantRefillTokenBucket(100, 1);

export const onRequest = defineMiddleware(async (context, next) => {
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null) {
		let cost: number;
		if (context.request.method === "GET" || context.request.method === "OPTIONS") {
			cost = 1;
		} else {
			cost = 2;
		}
		if (!bucket.check(clientIP, cost)) {
			return new Response("Too many requests", {
				status: 429
			});
		}
	}
	const sessionId = context.cookies.get(lucia.sessionCookieName)?.value ?? null;
	if (sessionId === null) {
		context.locals.session = null;
		context.locals.user = null;
		return next();
	}
	const { session, user } = await lucia.validateSession(sessionId);
	if (session !== null) {
		const sessionCookie = lucia.createSessionCookie(session.id, session.expiresAt);
		context.cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.npmCookieOptions());
	} else {
		const sessionCookie = lucia.createBlankSessionCookie();
		context.cookies.set(sessionCookie.name, sessionCookie.value, sessionCookie.npmCookieOptions());
	}
	context.locals.session = session;
	context.locals.user = user;
	return next();
});
