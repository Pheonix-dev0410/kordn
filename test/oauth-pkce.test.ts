import { describe, expect, it } from 'vitest';
import { isValidChallenge, isValidVerifier, verifyS256 } from '../src/oauth/pkce.js';

const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

describe('PKCE', () => {
  it('accepts the RFC 7636 Appendix B vector', () => {
    expect(verifyS256(verifier, challenge)).toBe(true);
  });

  it('rejects a wrong verifier', () => {
    expect(verifyS256('x'.repeat(43), challenge)).toBe(false);
  });

  it('validates verifier shape', () => {
    expect(isValidVerifier(verifier)).toBe(true);
    expect(isValidVerifier('a'.repeat(42))).toBe(false);
    expect(isValidVerifier('a'.repeat(43))).toBe(true);
    expect(isValidVerifier('a'.repeat(128))).toBe(true);
    expect(isValidVerifier('a'.repeat(129))).toBe(false);
    expect(isValidVerifier('a'.repeat(42) + ' ')).toBe(false);
    expect(isValidVerifier('a._~-'.repeat(9))).toBe(true);
  });

  it('validates challenge shape', () => {
    expect(isValidChallenge(challenge)).toBe(true);
    expect(isValidChallenge(challenge.slice(1))).toBe(false);
    expect(isValidChallenge(challenge + 'a')).toBe(false);
    expect(isValidChallenge(challenge.slice(1) + '=')).toBe(false);
  });
});
