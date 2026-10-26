import { createHash, timingSafeEqual } from 'node:crypto';

/** RFC 7636 §4.1: 43–128 chars of [A-Za-z0-9._~-]. */
export function isValidVerifier(verifier: string): boolean {
  return /^[A-Za-z0-9._~-]{43,128}$/.test(verifier);
}

/** A SHA-256 digest in unpadded base64url is always 43 characters. */
export function isValidChallenge(challenge: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(challenge);
}

export function verifyS256(verifier: string, challenge: string): boolean {
  if (!isValidVerifier(verifier) || !isValidChallenge(challenge)) return false;
  const expected = createHash('sha256').update(verifier, 'ascii').digest();
  return timingSafeEqual(expected, Buffer.from(challenge, 'base64url'));
}
