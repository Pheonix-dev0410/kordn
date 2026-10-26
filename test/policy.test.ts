import { describe, expect, it } from 'vitest';
import fixture from '../examples/policy.json' with { type: 'json' };
import { evaluate } from '../src/policy.js';
import { Policy } from '../src/schema.js';
import type { EvaluateInput, ToolCall } from '../src/schema.js';

const policy = Policy.parse(fixture);
const transfer: ToolCall = {
  tool: 'af_propose_transfer', resourceId: policy.resourceId, payeeId: 'utilities',
  amountMinor: 7500, currency: 'USD', idempotencyKey: 'request-0001',
};
const base: EvaluateInput = {
  agentId: policy.agentId, policy, call: transfer, revoked: false,
  usage: { reads: 0, transfers: 0, transferredMinor: 0 }, nowMs: Date.UTC(2026, 9, 25, 12),
};
const deny = (code: string) => ({ kind: 'deny', code });

describe('evaluate', () => {
  it.each([[1, 'allow'], [7500, 'allow'], [7501, 'require_approval'], [10000, 'require_approval'], [10001, 'deny']])(
    'checks single and approval boundaries at %s cents', (amountMinor, kind) => {
      expect(evaluate({ ...base, call: { ...transfer, amountMinor } })).toEqual(
        kind === 'deny' ? deny('SINGLE_LIMIT') : { kind },
      );
    },
  );

  it('only allows transfers in the policy currency', () => {
    expect(evaluate({ ...base, call: { ...transfer, currency: 'EUR' as 'USD' } })).toEqual(deny('INVALID_ARGUMENTS'));
  });

  it('checks identity and resource before capability, payee, amount and usage', () => {
    const bad = { ...base, call: { ...transfer, payeeId: 'attacker', amountMinor: 10100 },
      usage: { reads: 5, transfers: 3, transferredMinor: 25000 } };
    expect(evaluate({ ...bad, revoked: true })).toEqual(deny('SESSION_REVOKED'));
    expect(evaluate({ ...bad, agentId: 'other' })).toEqual(deny('INVALID_ARGUMENTS'));
    expect(evaluate({ ...bad, call: { ...bad.call, resourceId: 'mock-bank:other' } })).toEqual(deny('INVALID_ARGUMENTS'));
    expect(evaluate({ ...bad, policy: { ...policy, transfers: { ...policy.transfers, allow: false } } })).toEqual(deny('CAPABILITY_DISABLED'));
    expect(evaluate(bad)).toEqual(deny('UNAPPROVED_PAYEE'));
    expect(evaluate({ ...bad, call: transfer })).toEqual(deny('FREQUENCY_LIMIT'));
  });

  it.each([-1, 0, 0.1, NaN, Infinity])('rejects malformed amount %s', (amountMinor) => {
    expect(evaluate({ ...base, call: { ...transfer, amountMinor } })).toEqual(deny('INVALID_ARGUMENTS'));
  });

  it('rejects currency and unknown tools at runtime', () => {
    expect(evaluate({ ...base, call: { ...transfer, currency: 'EUR' } as unknown as ToolCall })).toEqual(deny('INVALID_ARGUMENTS'));
    expect(evaluate({ ...base, call: { tool: 'shell' } as unknown as ToolCall })).toEqual(deny('UNKNOWN_ACTION'));
  });

  it('allows exactly the count and cumulative limits, then denies', () => {
    expect(evaluate({ ...base, usage: { ...base.usage, transfers: 2, transferredMinor: 17500 } })).toEqual({ kind: 'allow' });
    expect(evaluate({ ...base, usage: { ...base.usage, transfers: 3 } })).toEqual(deny('FREQUENCY_LIMIT'));
    expect(evaluate({ ...base, usage: { ...base.usage, transferredMinor: 17501 } })).toEqual(deny('CUMULATIVE_LIMIT'));
  });

  it('checks read count, capability, row and UTC lookback limits', () => {
    const read: EvaluateInput = { ...base, call: {
      tool: 'af_list_transactions', resourceId: policy.resourceId, fromDate: '2026-09-25', limit: 20,
    } };
    expect(evaluate({ ...read, usage: { ...base.usage, reads: 4 } })).toEqual({ kind: 'allow' });
    expect(evaluate({ ...read, usage: { ...base.usage, reads: 5 } })).toEqual(deny('FREQUENCY_LIMIT'));
    expect(evaluate({ ...read, policy: { ...policy, reads: { ...policy.reads, allow: false } } })).toEqual(deny('CAPABILITY_DISABLED'));
    for (const fromDate of ['2026-09-24', '2026-10-26', 'bad-date']) {
      expect(evaluate({ ...read, call: { ...read.call, fromDate } as ToolCall })).toEqual(deny('INVALID_ARGUMENTS'));
    }
    expect(evaluate({ ...read, policy: { ...policy, reads: { ...policy.reads, maxRowsPerCall: 19 } } })).toEqual(deny('INVALID_ARGUMENTS'));
    for (const call of [
      { tool: 'af_get_balance', resourceId: policy.resourceId },
      { tool: 'af_get_transfer_status', transferRef: 'tr_0123456789abcdef' },
    ] as ToolCall[]) {
      expect(evaluate({ ...base, call })).toEqual({ kind: 'allow' });
      expect(evaluate({ ...base, call, usage: { ...base.usage, reads: 5 } })).toEqual(
        call.tool === 'af_get_transfer_status' ? { kind: 'allow' } : deny('FREQUENCY_LIMIT'),
      );
    }
  });
});
