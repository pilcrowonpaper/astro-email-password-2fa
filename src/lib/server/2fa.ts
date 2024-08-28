import { FixedRefillTokenBucket } from "./rate-limit";

export const totpBucket = new FixedRefillTokenBucket<number>(5, 60 * 30);
export const recoveryCodeBucket = new FixedRefillTokenBucket<number>(5, 60 * 60);
