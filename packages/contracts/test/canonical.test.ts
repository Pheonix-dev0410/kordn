import { describe, expect, it } from 'vitest';
import { canonicalJson, requestHash } from '../src';

describe('canonical encoding', () => {
  it('is independent of key order', () => {
    expect(canonicalJson({ b: 1, a: { d: [1, 2], c: 'x' } })).toBe('{"a":{"c":"x","d":[1,2]},"b":1}');
    expect(requestHash({ a: 1, b: 2 })).toBe(requestHash({ b: 2, a: 1 }));
  });

  it('distinguishes different bodies', () => {
    expect(requestHash({ amountMinor: 6000 })).not.toBe(requestHash({ amountMinor: 6001 }));
  });

  it('refuses values without a canonical form', () => {
    expect(() => canonicalJson({ a: Number.NaN })).toThrow();
    expect(() => canonicalJson({ a: undefined })).toThrow();
    expect(() => canonicalJson(new Date())).toThrow();
  });

  it('produces sha256: prefixed digests', () => {
    expect(requestHash({})).toMatch(/^sha256:[0-9a-f]{64}$/);
  });
});
