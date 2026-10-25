import { afterEach, describe, expect, it, vi } from 'vitest';
import { Ledger } from '../src/ledger.js';
import { harness, propose, transfer } from './helpers.js';
import { join } from 'node:path';

let h: ReturnType<typeof harness>;
afterEach(() => { vi.restoreAllMocks(); h?.close(); });

describe('guardian', () => {
  it('commits reservation and DISPATCHING before executing the adapter', async () => {
    h = harness();
    const execute = h.bank.execute.bind(h.bank);
    vi.spyOn(h.bank, 'execute').mockImplementation(async (id, call) => {
      const observer = new Ledger(join(h.dir, 'ledger.sqlite'), h.clock);
      try {
        expect(observer.get(id)?.state).toBe('DISPATCHING');
        expect(observer.audit.verifyChain()).toBe(true);
        expect(observer.audit.list().some((e) => e.event === 'transfer.dispatching')).toBe(true);
      } finally { observer.close(); }
      return execute(id, call);
    });
    expect((await propose(h)).state).toBe('succeeded');
  });

  it('rejects unknown actions and unexpected fields without reaching the adapter', async () => {
    h = harness();
    const spy = vi.spyOn(h.bank, 'execute');
    await expect(h.guardian.handleCall(h.policy.agentId, 'shell', {})).rejects.toMatchObject({ code: 'UNKNOWN_ACTION' });
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId, agentId: 'other' })).rejects.toMatchObject({ code: 'INVALID_ARGUMENTS' });
    expect(spy).not.toHaveBeenCalled();
    expect(h.guardian.listActivity({ event: 'policy.denied' })).toHaveLength(2);
  });

  it('binds approval to the digest and one-use nonce', async () => {
    h = harness();
    const result = await propose(h, 0, 8000);
    expect(result.state).toBe('pending_approval');
    expect(result).not.toHaveProperty('nonce');
    const r = h.guardian.listPending()[0]!;
    await expect(h.guardian.approve(r.id, 'stale-digest', r.nonce!)).rejects.toMatchObject({ code: 'INVALID_ARGUMENTS' });
    await expect(h.guardian.approve(r.id, r.digest, 'wrong-nonce')).rejects.toMatchObject({ code: 'INVALID_ARGUMENTS' });
    expect((await h.guardian.approve(r.id, r.digest, r.nonce!)).state).toBe('succeeded');
    await expect(h.guardian.approve(r.id, r.digest, r.nonce!)).rejects.toMatchObject({ code: 'INVALID_ARGUMENTS' });
    expect((await h.bank.getBalance(h.policy.resourceId)).balanceMinor).toBe(482315 - 8000);
  });

  it('rejects expired approvals and permits explicit rejection only once', async () => {
    h = harness();
    await propose(h, 0, 8000);
    const r = h.guardian.listPending()[0]!;
    h.advance(300_000);
    await expect(h.guardian.approve(r.id, r.digest, r.nonce!)).rejects.toMatchObject({ code: 'APPROVAL_EXPIRED' });
    expect(h.ledger.get(r.id)?.state).toBe('EXPIRED');
    await propose(h, 1, 8000);
    const next = h.guardian.listPending()[0]!;
    expect(h.guardian.reject(next.id, next.nonce!).state).toBe('REJECTED');
    expect(() => h.guardian.reject(next.id, next.nonce!)).toThrow();
  });

  it('re-checks policy changes at approval and cannot override a hard deny', async () => {
    h = harness();
    await propose(h, 0, 8000);
    const r = h.guardian.listPending()[0]!;
    const policy = structuredClone(h.policy);
    policy.transfers.maxSingleMinor = 7500;
    h.guardian.updatePolicy(policy, 1);
    await expect(h.guardian.approve(r.id, r.digest, r.nonce!)).rejects.toMatchObject({ code: 'SINGLE_LIMIT' });
    expect(h.ledger.get(r.id)?.state).toBe('REJECTED');
  });

  it('denies after revoke and rejects pending approvals', async () => {
    h = harness();
    await propose(h, 0, 8000);
    const r = h.guardian.listPending()[0]!;
    h.guardian.revoke(h.policy.agentId);
    expect(h.guardian.listPending()).toHaveLength(0);
    await expect(h.guardian.approve(r.id, r.digest, r.nonce!)).rejects.toMatchObject({ code: 'INVALID_ARGUMENTS' });
    await expect(propose(h, 1)).rejects.toMatchObject({ code: 'SESSION_REVOKED' });
  });

  it('keeps quota for a lost response and resolves it without sending again', async () => {
    h = harness();
    h.bank.faults.responseLost = true;
    const result = await propose(h);
    expect(result.state).toBe('unknown');
    const execute = vi.spyOn(h.bank, 'execute');
    await h.guardian.reconcile();
    expect(h.ledger.get(result.transferRef)?.state).toBe('SUCCEEDED');
    expect(execute).not.toHaveBeenCalled();
    expect(h.ledger.audit.verifyChain()).toBe(true);
  });

  it('holds quota on exceptions and on timeouts while the adapter is still running', async () => {
    h = harness(undefined, 10);
    h.bank.faults.delayMs = 80;
    const result = await propose(h);
    expect(result.state).toBe('unknown');
    await h.guardian.reconcile();
    expect(h.ledger.get(result.transferRef)?.state).toBe('UNKNOWN');
    await new Promise((resolve) => setTimeout(resolve, 100));
    await h.guardian.reconcile();
    expect(h.ledger.get(result.transferRef)?.state).toBe('SUCCEEDED');
    vi.spyOn(h.bank, 'execute').mockRejectedValue(new Error('connection lost'));
    const second = await propose(h, 2);
    expect(second.state).toBe('unknown');
  });

  it('fails closed if the database or audit writer is unavailable', async () => {
    h = harness();
    const spy = vi.spyOn(h.bank, 'execute');
    h.ledger.db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'unavailable'); END");
    await expect(propose(h)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect(spy).not.toHaveBeenCalled();
    h.ledger.db.exec('DROP TRIGGER fail_audit');
    vi.spyOn(h.ledger, 'admit').mockImplementation(() => { throw new Error('database closed'); });
    await expect(propose(h)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect(spy).not.toHaveBeenCalled();
  });

  it('validates adapter outputs and does not accept malformed success results', async () => {
    h = harness();
    vi.spyOn(h.bank, 'execute').mockResolvedValue({ state: 'succeeded' } as never);
    expect((await propose(h)).state).toBe('unknown');
    vi.spyOn(h.bank, 'listTransactions').mockResolvedValue({ transactions: [] });
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_list_transactions', {
      resourceId: h.policy.resourceId, fromDate: '2026-10-01', limit: 5,
    })).resolves.toEqual({ transactions: [] });
  });

  it('does not overwrite reconciliation if execution returns its lost response later', async () => {
    h = harness();
    const execute = h.bank.execute.bind(h.bank);
    vi.spyOn(h.bank, 'execute').mockImplementation(async (id, call) => {
      await execute(id, call);
      await h.guardian.reconcile();
      return { state: 'unknown', correlationId: id };
    });
    expect((await propose(h)).state).toBe('succeeded');
    expect(h.ledger.list()[0]!.state).toBe('SUCCEEDED');
  });

  it('filters terminal history in SQL before decoding lifecycle work', async () => {
    h = harness();
    for (let i = 100; i < 110; i++) {
      const admission = h.ledger.admit(h.policy.agentId, transfer(i));
      if (admission.kind !== 'transfer') throw new Error('missing reservation');
      h.ledger.dispatch(admission.reservation.id);
      h.ledger.transition(admission.reservation.id, 'FAILED');
    }
    // An irrelevant historical payload must never be decoded by active-state queries.
    h.ledger.db.exec("UPDATE reservations SET call_json='not-json' WHERE state='FAILED'");
    h.bank.faults.responseLost = true;
    const unknown = await propose(h, 1);
    h.bank.faults.responseLost = false;
    const expired = await propose(h, 2, 8000);
    h.advance(300_000);
    const pending = await propose(h, 3, 8000);
    expect(h.guardian.listPending().map((r) => r.id)).toEqual([pending.transferRef]);
    expect(h.ledger.get(expired.transferRef)?.state).toBe('EXPIRED');
    await h.guardian.reconcile();
    expect(h.ledger.get(unknown.transferRef)?.state).toBe('SUCCEEDED');
    h.guardian.revoke();
    expect(h.ledger.get(pending.transferRef)?.state).toBe('REJECTED');
    expect(h.guardian.listPending()).toEqual([]);
    expect(h.ledger.audit.verifyChain()).toBe(true);
  });
});
