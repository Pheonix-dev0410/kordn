import { describe, expect, it } from 'vitest';
import policy from '../examples/policy.json' with { type: 'json' };
import { BUDGET_STATES, canTransition, MAX_AMOUNT_MINOR, parseToolCall, Policy, SocketRequest, TOOL_NAMES } from '../src/schema.js';
import { canonicalJson, requestHash } from '../src/hash.js';

const transfer = {
  resourceId: 'mock-bank:checking-01',
  payeeId: 'utilities',
  amountMinor: 6000,
  currency: 'USD',
  idempotencyKey: 'random-client-uuid',
};

describe('policy', () => {
  it('accepts examples/policy.json', () => {
    expect(Policy.safeParse(policy).success).toBe(true);
  });

  it('rejects unknown keys, allow-by-default, non-USD and single > cumulative', () => {
    expect(Policy.safeParse({ ...policy, extra: 1 }).success).toBe(false);
    expect(Policy.safeParse({ ...policy, defaultDecision: 'allow' }).success).toBe(false);
    expect(Policy.safeParse({ ...policy, transfers: { ...policy.transfers, currency: 'EUR' } }).success).toBe(false);
    expect(Policy.safeParse({ ...policy, transfers: { ...policy.transfers, maxSingleMinor: 30000 } }).success).toBe(false);
  });
});

describe('tool calls', () => {
  it('has exactly four tools', () => {
    expect(TOOL_NAMES).toHaveLength(4);
  });

  it('parses a valid transfer', () => {
    expect(parseToolCall('af_propose_transfer', transfer)).toEqual({ tool: 'af_propose_transfer', ...transfer });
  });

  it('rejects unknown tools', () => {
    for (const t of ['af_add_payee', 'shell', '', null]) expect(parseToolCall(t, {})).toBeNull();
  });

  it('rejects extra fields like policyApproved or agentId', () => {
    expect(parseToolCall('af_propose_transfer', { ...transfer, policyApproved: true })).toBeNull();
    expect(parseToolCall('af_propose_transfer', { ...transfer, agentId: 'other' })).toBeNull();
  });

  it.each([-1, 0, 0.5, Number.NaN, Infinity, MAX_AMOUNT_MINOR + 1, '6000'])('rejects amount %s', (amountMinor) => {
    expect(parseToolCall('af_propose_transfer', { ...transfer, amountMinor })).toBeNull();
  });

  it('caps transaction reads at 20 rows', () => {
    const base = { resourceId: 'mock-bank:checking-01', fromDate: '2026-10-01' };
    expect(parseToolCall('af_list_transactions', { ...base, limit: 20 })).not.toBeNull();
    expect(parseToolCall('af_list_transactions', { ...base, limit: 21 })).toBeNull();
  });
});

describe('lifecycle', () => {
  it('UNKNOWN only resolves to SUCCEEDED or FAILED and keeps holding budget', () => {
    expect(canTransition('UNKNOWN', 'SUCCEEDED')).toBe(true);
    expect(canTransition('UNKNOWN', 'REJECTED')).toBe(false);
    expect(BUDGET_STATES).toContain('UNKNOWN');
    expect(BUDGET_STATES).not.toContain('FAILED');
  });
});

describe('socket protocol', () => {
  it('has no identity or approval fields', () => {
    const frame = { v: 1, id: 'c1', tool: 'af_get_balance', args: {} };
    expect(SocketRequest.safeParse(frame).success).toBe(true);
    expect(SocketRequest.safeParse({ ...frame, agentId: 'x' }).success).toBe(false);
  });
});

describe('hashing', () => {
  it('is independent of key order and rejects non-canonical values', () => {
    expect(canonicalJson({ b: 1, a: [1, 'x'] })).toBe('{"a":[1,"x"],"b":1}');
    expect(requestHash({ a: 1, b: 2 })).toBe(requestHash({ b: 2, a: 1 }));
    expect(() => canonicalJson({ a: Number.NaN })).toThrow();
    expect(() => canonicalJson({ a: undefined })).toThrow();
  });
});
