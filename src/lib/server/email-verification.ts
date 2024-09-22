import { generateRandomOTP } from "./utils";
import { db } from "./db";
import { FixedRefillTokenBucket } from "./rate-limit";
import { encodeBase32 } from "@oslojs/encoding";

import type { APIContext } from "astro";

export function getEmailVerificationRequest(id: string): EmailVerificationRequest | null {
	const row = db.queryOne("SELECT id, user_id, code, email, expires_at FROM email_verification_request WHERE id = ?", [
		id
	]);
	if (row === null) {
		return row;
	}
	const request: EmailVerificationRequest = {
		id: row.string(0),
		userId: row.number(1),
		code: row.string(2),
		email: row.string(3),
		expiresAt: new Date(row.number(4) * 1000)
	};
	return request;
}

export function createEmailVerificationRequest(userId: number, email: string): EmailVerificationRequest {
	deleteUserEmailVerificationRequest(userId);
	const idBytes = new Uint8Array(20);
	crypto.getRandomValues(idBytes);
	const id = encodeBase32(idBytes).toLowerCase();

	const code = generateRandomOTP();
	const expiresAt = new Date(Date.now() + 1000 * 60 * 10);
	db.queryOne(
		"INSERT INTO email_verification_request (id, user_id, code, email, expires_at) VALUES (?, ?, ?, ?, ?) RETURNING id",
		[id, userId, code, email, Math.floor(expiresAt.getTime() / 1000)]
	);

	const request: EmailVerificationRequest = {
		id,
		userId,
		code,
		email,
		expiresAt
	};
	return request;
}

export function deleteUserEmailVerificationRequest(userId: number): void {
	db.execute("DELETE FROM email_verification_request WHERE user_id = ?", [userId]);
}

export function sendVerificationEmail(email: string, code: string): void {
	console.log(`To ${email}: Your verification code is ${code}`);
}

export function setEmailVerificationRequestCookie(context: APIContext, request: EmailVerificationRequest): void {
	context.cookies.set("email_verification", request.id, {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		expires: request.expiresAt
	});
}

export function deleteEmailVerificationRequestCookie(context: APIContext): void {
	context.cookies.set("email_verification", "", {
		httpOnly: true,
		path: "/",
		secure: import.meta.env.PROD,
		sameSite: "lax",
		maxAge: 0
	});
}

export function getUserEmailVerificationRequestFromRequest(context: APIContext): EmailVerificationRequest | null {
	if (context.locals.user === null) {
		return null;
	}
	const id = context.cookies.get("email_verification")?.value ?? null;
	if (id === null) {
		return null;
	}
	const request = getEmailVerificationRequest(id);
	if (request !== null && request.userId !== context.locals.user.id) {
		deleteEmailVerificationRequestCookie(context);
		return null;
	}
	return request;
}

export const sendVerificationEmailBucket = new FixedRefillTokenBucket<number>(3, 60 * 10);

export interface EmailVerificationRequest {
	id: string;
	userId: number;
	code: string;
	email: string;
	expiresAt: Date;
}
