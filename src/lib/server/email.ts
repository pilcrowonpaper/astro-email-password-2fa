import { db } from "./db";

export function verifyEmailInput(email: string): boolean {
	return /^.+@.+\..+$/.test(email) && email.length < 256;
}

export function checkEmailAvailability(email: string): boolean {
	const row = db.queryOne("SELECT COUNT(*) FROM user WHERE email = ?", [email]);
	if (row === null) {
		throw new Error();
	}
	return row.number(0) === 0;
}
