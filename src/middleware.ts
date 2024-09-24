import { defineMiddleware, sequence } from "astro:middleware";
import { ConstantRefillTokenBucket } from "@lib/server/rate-limit";
import { deleteSessionTokenCookie, setSessionTokenCookie, validateSessionToken } from "@lib/server/session";

const bucket = new ConstantRefillTokenBucket(100, 1);

const rateLimitMiddleware = defineMiddleware((context, next) => {
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP === null) {
		return next();
	}
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
	return next();
});

const authMiddleware = defineMiddleware((context, next) => {
	const token = context.cookies.get("session")?.value ?? null;
	if (token === null) {
		context.locals.session = null;
		context.locals.user = null;
		return next();
	}
	const { user, session } = validateSessionToken(token);
	if (session !== null) {
		setSessionTokenCookie(context, token, session.expiresAt);
	} else {
		deleteSessionTokenCookie(context);
	}
	context.locals.session = session;
	context.locals.user = user;
	return next();
});

export const onRequest = sequence(rateLimitMiddleware, authMiddleware);
