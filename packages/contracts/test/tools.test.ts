import { describe, expect, it } from 'vitest';
import { GetBalanceOutput, MAX_AMOUNT_MINOR, parseToolCall, TOOL_NAMES } from '../src';

const transfer = {
  resourceId: 'mock-bank:checking-01',
  payeeId: 'utilities',
  amountMinor: 6000,
  currency: 'USD',
  idempotencyKey: 'random-client-uuid',
};

describe('tool input parsing', () => {
  it('exposes exactly the four v0.1 tools', () => {
    expect(TOOL_NAMES).toEqual(['af_get_balance', 'af_list_transactions', 'af_propose_transfer', 'af_get_transfer_status']);
  });

  it('parses a valid transfer', () => {
    expect(parseToolCall('af_propose_transfer', transfer)).toEqual({ tool: 'af_propose_transfer', ...transfer });
  });

  it('rejects unknown tools (T19)', () => {
    for (const t of ['af_add_payee', 'shell', 'browser_click', '', null, 42]) {
      expect(parseToolCall(t, {})).toBeNull();
    }
  });

  it('rejects unknown fields, e.g. policyApproved or agentId (§7.4)', () => {
    expect(parseToolCall('af_propose_transfer', { ...transfer, policyApproved: true })).toBeNull();
    expect(parseToolCall('af_propose_transfer', { ...transfer, agentId: 'someone-else' })).toBeNull();
  });

  it.each([-1, 0, 0.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_AMOUNT_MINOR + 1, '6000', 2 ** 63])(
    'rejects malformed amount %s (T09)',
    (amountMinor) => {
      expect(parseToolCall('af_propose_transfer', { ...transfer, amountMinor })).toBeNull();
    },
  );

  it('rejects non-USD', () => {
    expect(parseToolCall('af_propose_transfer', { ...transfer, currency: 'EUR' })).toBeNull();
  });

  it('caps list_transactions at 20 rows (T01)', () => {
    const base = { resourceId: 'mock-bank:checking-01', fromDate: '2026-10-01' };
    expect(parseToolCall('af_list_transactions', { ...base, limit: 20 })).not.toBeNull();
    expect(parseToolCall('af_list_transactions', { ...base, limit: 21 })).toBeNull();
  });

  it('rejects forged transfer refs', () => {
    expect(parseToolCall('af_get_transfer_status', { transferRef: '../../etc/passwd' })).toBeNull();
  });

  it('outputs are strict too', () => {
    const ok = { currency: 'USD', balanceMinor: 100, observedAt: '2026-10-25T12:00:00Z' };
    expect(GetBalanceOutput.safeParse(ok).success).toBe(true);
    expect(GetBalanceOutput.safeParse({ ...ok, accountNumber: '123' }).success).toBe(false);
  });
});
