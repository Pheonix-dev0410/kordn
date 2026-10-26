import { afterEach, describe, expect, it } from 'vitest';
import { harness, propose, transfer } from './helpers.js';

let h: ReturnType<typeof harness>;
afterEach(() => h?.close());

describe('SQLite ledger', () => {
  it('enforces the read limit and slides the window at one hour', async () => {
    h = harness();
    for (let i = 0; i < 5; i++) await h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId });
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId })).resolves.toMatchObject({ ok: false, error: { code: 'FREQUENCY_LIMIT' } });
    h.advance(3_600_000 - 1);
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId })).resolves.toMatchObject({ ok: false, error: { code: 'FREQUENCY_LIMIT' } });
    h.advance(1);
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId })).resolves.toMatchObject({ ok: true, result: { balanceMinor: expect.any(Number) } });
  });

  it('enforces count and resets completed transfers after 24h', async () => {
    h = harness();
    for (let i = 0; i < 3; i++) expect((await propose(h, i)).state).toBe('succeeded');
    await expect(propose(h, 3)).rejects.toMatchObject({ code: 'FREQUENCY_LIMIT' });
    h.advance(86_400_000);
    expect((await propose(h, 4)).state).toBe('succeeded');
  });

  it('reserves pending amounts and rejects the first dollar over the cumulative limit', () => {
    h = harness();
    const a = h.ledger.admit(h.policy.agentId, transfer(1, 10000));
    const b = h.ledger.admit(h.policy.agentId, transfer(2, 10000));
    expect(a.kind).toBe('transfer');
    expect(b.kind).toBe('transfer');
    expect(() => h.ledger.admit(h.policy.agentId, transfer(3, 5001))).toThrow(expect.objectContaining({ code: 'CUMULATIVE_LIMIT' }));
    expect(h.ledger.admit(h.policy.agentId, transfer(4, 5000)).kind).toBe('transfer');
  });

  it('holds UNKNOWN past the rolling window and releases only a definite failure', () => {
    h = harness();
    const policy = structuredClone(h.policy);
    policy.transfers.maxCalls = 1;
    h.ledger.updatePolicy(policy, 1);
    const admission = h.ledger.admit(policy.agentId, transfer());
    if (admission.kind !== 'transfer') throw new Error('missing transfer');
    h.ledger.dispatch(admission.reservation.id);
    h.ledger.transition(admission.reservation.id, 'UNKNOWN');
    h.advance(2 * 86_400_000);
    expect(() => h.ledger.admit(policy.agentId, transfer(2))).toThrow(expect.objectContaining({ code: 'FREQUENCY_LIMIT' }));
    expect(() => h.ledger.transition(admission.reservation.id, 'REJECTED')).toThrow();
    h.ledger.transition(admission.reservation.id, 'FAILED');
    expect(h.ledger.admit(policy.agentId, transfer(2)).kind).toBe('transfer');
  });

  it('returns one reservation for fifty identical calls and rejects a changed body', async () => {
    h = harness();
    const results = await Promise.all(Array.from({ length: 50 }, () => propose(h)));
    expect(new Set(results.map((r) => r.transferRef)).size).toBe(1);
    expect(h.ledger.list()).toHaveLength(1);
    expect((await h.bank.getBalance(h.policy.resourceId)).balanceMinor).toBe(482315 - 5000);
    await expect(propose(h, 0, 5001)).rejects.toMatchObject({ code: 'IDEMPOTENCY_CONFLICT' });
    expect(h.ledger.list()).toHaveLength(1);
  });

  it('rolls back quota and evidence together if the audit insert fails', () => {
    h = harness();
    h.ledger.db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'disk failure'); END");
    expect(() => h.ledger.admit(h.policy.agentId, transfer())).toThrow();
    expect(h.ledger.list()).toHaveLength(0);
    expect(h.ledger.audit.verifyChain()).toBe(true);
  });

  it('does not leak another agent’s transfer and does not charge polls to reads', async () => {
    h = harness();
    const ref = (await propose(h)).transferRef;
    for (let i = 0; i < 60; i++) {
      await h.guardian.handleCall(h.policy.agentId, 'af_get_transfer_status', { transferRef: ref });
    }
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_transfer_status', { transferRef: ref })).resolves.toMatchObject({ ok: false, error: { code: 'RATE_LIMITED' } });
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_balance', { resourceId: h.policy.resourceId })).resolves.toMatchObject({ ok: true, result: { balanceMinor: expect.any(Number) } });
    h.advance(60_000);
    await expect(h.guardian.handleCall(h.policy.agentId, 'af_get_transfer_status', { transferRef: ref })).resolves.toMatchObject({ ok: true, result: { state: 'SUCCEEDED' } });
    const other = { ...structuredClone(h.policy), agentId: 'other-agent' };
    h.ledger.updatePolicy(other, 0);
    expect(() => h.ledger.admit(other.agentId, { tool: 'af_get_transfer_status', transferRef: ref }))
      .toThrow(expect.objectContaining({ code: 'INVALID_ARGUMENTS' }));
  });

  it('rejects stale policy writes and cannot clear revocation through a policy edit', async () => {
    h = harness();
    expect(await h.guardian.updatePolicy(h.policy, 0)).toEqual({ ok: false, code: 'VERSION_CONFLICT' });
    await h.guardian.revoke(h.policy.agentId);
    await h.guardian.updatePolicy(h.policy, 1);
    expect(await h.guardian.isRevoked(h.policy.agentId)).toBe(true);
  });
});
