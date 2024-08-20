import { encodeBase32 } from "@oslojs/encoding";

export function verifyExpirationDate(expiresAt: Date): boolean {
	return Date.now() < expiresAt.getTime();
}

export function generateRandomOTP(): string {
	const bytes = new Uint8Array(5);
	crypto.getRandomValues(bytes);
	const code = encodeBase32(bytes);
	return code;
}
