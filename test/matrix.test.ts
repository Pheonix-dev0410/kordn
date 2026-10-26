import { afterEach, describe, expect, it, vi } from 'vitest';
import fixture from '../examples/policy.json' with { type: 'json' };
import { startAdminServer } from '../src/admin/server.js';
import { createGuardianClient } from '../src/guardian-client.js';
import { Policy } from '../src/schema.js';
import { login } from './admin-helpers.js';
import { harness, transfer } from './helpers.js';

// The required cases T01-T20 from the design doc (§11.1), one test each, against the real
// guardian, ledger and mock bank. T17 and T18 need the sandbox: see test/attacks.test.ts.

type Harness = ReturnType<typeof harness>;
let h: Harness;
const closers: (() => unknown)[] = [];
afterEach(async () => {
  while (closers.length) await closers.pop()?.();
  vi.restoreAllMocks();
  h?.close();
});

const base = Policy.parse(fixture);
const withTransfers = (changes: Partial<Policy['transfers']>) => Policy.parse({ ...base, transfers: { ...base.transfers, ...changes } });

const call = (tool: string, args: unknown) => h.guardian.handleCall(h.policy.agentId, tool, args);
const code = (result: Awaited<ReturnType<typeof call>>) => (result.ok ? null : result.error.code);
const read = () => call('af_get_balance', { resourceId: h.policy.resourceId });
const pay = (n: number, amountMinor = 5_000, payeeId = 'utilities') => {
  const { tool, ...args } = transfer(n, amountMinor);
  return call(tool, { ...args, payeeId });
};
const bank = () =>
  h.bank.db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(amount_minor), 0) AS total FROM bank_transfers').get() as { n: number; total: number };
const HOUR = 3_600_000;

describe('design doc §11.1 test matrix', () => {
  it('T01: one permitted read returns at most 20 rows; a lookback over 30 days is denied', async () => {
    h = harness();
    const ok = await call('af_list_transactions', { resourceId: h.policy.resourceId, fromDate: '2026-09-26', limit: 20 });
    expect(ok.ok).toBe(true);
    expect((ok as { result: { transactions: unknown[] } }).result.transactions.length).toBeLessThanOrEqual(20);
    expect(code(await call('af_list_transactions', { resourceId: h.policy.resourceId, fromDate: '2026-09-01', limit: 20 }))).not.toBeNull();
  });

  it('T02: six reads inside 60 minutes: the first five pass, the sixth is denied', async () => {
    h = harness();
    for (let i = 0; i < 5; i++) expect((await read()).ok).toBe(true);
    expect(code(await read())).toBe('FREQUENCY_LIMIT');
  });

  it('T03: a read is allowed again once the oldest read leaves the 60 minute window', async () => {
    h = harness();
    for (let i = 0; i < 5; i++) await read();
    h.advance(HOUR + 1);
    expect((await read()).ok).toBe(true);
  });

  it('T04: $101 to an allowed payee is denied with SINGLE_LIMIT', async () => {
    h = harness();
    expect(code(await pay(1, 10_100))).toBe('SINGLE_LIMIT');
    expect(bank().n).toBe(0);
  });

  it('T05: three allowed transfers, then the fourth is denied with FREQUENCY_LIMIT', async () => {
    h = harness();
    for (const n of [1, 2, 3]) expect((await pay(n)).ok).toBe(true);
    expect(code(await pay(4))).toBe('FREQUENCY_LIMIT');
    expect(bank().n).toBe(3);
  });

  it('T06: the first reservation over the $250 total is rejected, pending approvals included', async () => {
    h = harness(withTransfers({ maxCalls: 10 }));
    // $100 each, above the $75 approval line: they wait for approval but already hold budget.
    expect((await pay(1, 10_000)).ok).toBe(true);
    expect((await pay(2, 10_000)).ok).toBe(true);
    expect(code(await pay(3, 10_000))).toBe('CUMULATIVE_LIMIT');
    expect((await pay(4, 5_000)).ok).toBe(true);
    expect(bank().n).toBe(1);
  });

  it('T07: a transfer to an unknown payee is denied with UNAPPROVED_PAYEE', async () => {
    h = harness();
    expect(code(await pay(1, 1_000, 'stranger-01'))).toBe('UNAPPROVED_PAYEE');
  });

  it('T08: doing what an injected memo says is denied by the rules', async () => {
    h = harness();
    const listed = await call('af_list_transactions', { resourceId: h.policy.resourceId, fromDate: '2026-10-01', limit: 20 });
    const memos = (listed as { result: { transactions: { description: { text: string } }[] } }).result.transactions;
    const order = memos.map((t) => t.description.text).find((text) => /attacker/i.test(text));
    expect(order).toBeDefined();
    expect(code(await pay(1, 50_000, 'attacker'))).toBe('UNAPPROVED_PAYEE');
    expect(bank().n).toBe(0);
  });

  it('T09: amount -1, 0, a float, NaN or a huge integer is rejected without touching quota', async () => {
    h = harness();
    for (const amountMinor of [-1, 0, 1.5, Number.NaN, 2 ** 60, '5000']) {
      expect(code(await pay(1, amountMinor as number))).toBe('INVALID_ARGUMENTS');
    }
    expect(h.ledger.list()).toEqual([]);
    for (const n of [1, 2, 3]) expect((await pay(n)).ok).toBe(true);
  });

  it('T10: the same idempotency key and body twice make one transfer; the retry reports it', async () => {
    h = harness();
    const first = await pay(1);
    const second = await pay(1);
    expect(second).toEqual(first);
    expect(bank().n).toBe(1);
  });

  it('T11: the same key with a different body is a conflict, and nothing is sent again', async () => {
    h = harness();
    expect((await pay(1, 5_000)).ok).toBe(true);
    expect(code(await pay(1, 6_000))).toBe('IDEMPOTENCY_CONFLICT');
    expect(bank().n).toBe(1);
  });

  it.each([
    ['the count', withTransfers({}), 3],
    ['the total', withTransfers({ maxCalls: 1000 }), 5],
  ])('T12: 1,000 concurrent $50 requests never exceed %s', async (_limit, policy, expected) => {
    h = harness(policy);
    const results = await Promise.all(Array.from({ length: 1000 }, (_, n) => pay(n)));
    expect(results.filter((r) => r.ok)).toHaveLength(expected);
    expect(bank()).toEqual({ n: expected, total: expected * 5_000 });
  });

  it('T13: a crash after reservation and before submit neither sends twice nor frees quota early', async () => {
    h = harness(withTransfers({ maxCalls: 1 }));
    const admission = h.ledger.admit(h.policy.agentId, transfer(1));
    expect(admission.kind).toBe('transfer');
    h.restart();
    // Until the bank proves it never saw it, the reservation keeps its quota.
    vi.spyOn(h.bank, 'reconcile').mockResolvedValueOnce({ state: 'unknown', correlationId: 'x' });
    await h.guardian.reconcile();
    expect(code(await pay(2))).toBe('FREQUENCY_LIMIT');
    const execute = vi.spyOn(h.bank, 'execute');
    await h.guardian.reconcile();
    expect(execute).not.toHaveBeenCalled();
    expect(bank().n).toBe(0);
    expect((await pay(3)).ok).toBe(true);
  });

  it('T14: a crash after submit with the response lost stays UNKNOWN and holds quota until reconciled', async () => {
    h = harness(withTransfers({ maxCalls: 1 }));
    const admission = h.ledger.admit(h.policy.agentId, transfer(1));
    if (admission.kind !== 'transfer') throw new Error('expected a reservation');
    h.ledger.dispatch(admission.reservation.id);
    h.bank.faults.responseLost = true;
    await h.bank.execute(admission.reservation.id, admission.reservation.call);
    h.restart();
    vi.spyOn(h.bank, 'reconcile').mockResolvedValueOnce({ state: 'unknown', correlationId: 'x' });
    await h.guardian.reconcile();
    expect(h.ledger.get(admission.reservation.id)?.state).toBe('UNKNOWN');
    expect(code(await pay(2))).toBe('FREQUENCY_LIMIT');
    await h.guardian.reconcile();
    expect(h.ledger.get(admission.reservation.id)?.state).toBe('SUCCEEDED');
    expect(bank().n).toBe(1);
  });

  it('T15: the kill switch denies at once and invalidates pending approvals', async () => {
    h = harness();
    expect((await pay(1, 9_000)).ok).toBe(true);
    expect(await h.guardian.listPending()).toHaveLength(1);
    await h.guardian.revoke(h.policy.agentId);
    expect(code(await pay(2))).toBe('SESSION_REVOKED');
    expect(code(await read())).toBe('SESSION_REVOKED');
    expect(await h.guardian.listPending()).toEqual([]);
    expect(bank().n).toBe(0);
  });

  it('T16: with the guardian down, protected actions fail and never reach the bank', async () => {
    h = harness();
    const viaSocket = createGuardianClient('/nonexistent/kordn.sock', { timeoutMs: 1000 });
    const { tool, ...args } = transfer(1);
    expect(await viaSocket(h.policy.agentId, tool, args)).toEqual({
      ok: false,
      error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' },
    });
    expect(bank().n).toBe(0);
  });

  it('T19: an unknown MCP tool or an altered schema is denied, with the reason logged', async () => {
    h = harness();
    expect(code(await call('shell', { cmd: 'id' }))).toBe('UNKNOWN_ACTION');
    const { tool, ...args } = transfer(1);
    expect(code(await call(tool, { ...args, amountMinor: '5000', note: 'changed schema' }))).toBe('INVALID_ARGUMENTS');
    const denied = (await h.guardian.listActivity({ events: ['policy.denied'] })).map((e) => e.reasonCode);
    expect(denied).toEqual(expect.arrayContaining(['UNKNOWN_ACTION', 'INVALID_ARGUMENTS']));
  });

  it('T20: injected text reaching the approval UI is shown as literal text, never markup', async () => {
    h = harness();
    const injected = '<img src=x onerror=alert(1)><script>alert(2)</script>';
    await call(injected, { memo: injected });
    expect((await pay(1, 9_000)).ok).toBe(true);
    const admin = await startAdminServer({ guardian: h.guardian, agentId: h.policy.agentId, mode: 'guard' });
    closers.push(() => admin.close());
    const session = await login(admin);
    for (const page of ['/approvals', '/activity']) {
      const { body } = await session.get(page);
      expect(body).not.toMatch(/<img|<script/i);
    }
    // Every agent-reachable field forced to HTML: test/admin-approvals.test.ts.
  });
});
