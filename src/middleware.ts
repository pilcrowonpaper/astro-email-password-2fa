import { defineMiddleware } from "astro:middleware";
import { ConstantRefillTokenBucket } from "@lib/server/rate-limit";
import { validateRequest } from "@lib/server/session";

const bucket = new ConstantRefillTokenBucket(100, 1);

export const onRequest = defineMiddleware((context, next) => {
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
	const { session, user } = validateRequest(context);
	context.locals.session = session;
	context.locals.user = user;
	return next();
});
