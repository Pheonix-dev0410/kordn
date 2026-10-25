import { describe, expect, it } from 'vitest';
import demoPolicy from '../../../examples/demo-policy.json' with { type: 'json' };
import { Policy } from '../src';

describe('Policy schema', () => {
  it('accepts examples/demo-policy.json', () => {
    expect(Policy.safeParse(demoPolicy).success).toBe(true);
  });

  it('rejects unknown keys at every level', () => {
    expect(Policy.safeParse({ ...demoPolicy, extra: 1 }).success).toBe(false);
    expect(Policy.safeParse({ ...demoPolicy, reads: { ...demoPolicy.reads, extra: 1 } }).success).toBe(false);
    expect(
      Policy.safeParse({ ...demoPolicy, transfers: { ...demoPolicy.transfers, policyApproved: true } }).success,
    ).toBe(false);
  });

  it('only allows default deny', () => {
    expect(Policy.safeParse({ ...demoPolicy, defaultDecision: 'allow' }).success).toBe(false);
  });

  it('rejects non-USD and single > cumulative', () => {
    expect(Policy.safeParse({ ...demoPolicy, transfers: { ...demoPolicy.transfers, currency: 'EUR' } }).success).toBe(
      false,
    );
    expect(
      Policy.safeParse({ ...demoPolicy, transfers: { ...demoPolicy.transfers, maxSingleMinor: 30000 } }).success,
    ).toBe(false);
  });
});
