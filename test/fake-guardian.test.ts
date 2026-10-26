import { describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from './fake-guardian.js';
import { APPROVAL_TTL_SEC, AuditEvent, Policy, TOOL_OUTPUTS, type ToolName } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const agent = policy.agentId;
const transfer = (amountMinor: number, payeeId = 'utilities') => ({
  resourceId: 'mock-bank:checking-01',
  payeeId,
  amountMinor,
  currency: 'USD',
  idempotencyKey: `key-${amountMinor}-${payeeId}`,
});

describe('fake guardian', () => {
  it('denies unknown tools and extra fields', async () => {
    const g = createFakeGuardian({ policy });
    expect(await g.handleCall(agent, 'shell', {})).toMatchObject({ ok: false, error: { code: 'UNKNOWN_ACTION' } });
    expect(await g.handleCall(agent, 'af_propose_transfer', { ...transfer(100), policyApproved: true })).toMatchObject({
      ok: false,
      error: { code: 'INVALID_ARGUMENTS' },
    });
    expect((await g.listActivity({ events: ['policy.denied'] })).map((e) => e.reasonCode)).toEqual([
      'INVALID_ARGUMENTS',
      'UNKNOWN_ACTION',
    ]);
  });

  it('applies payee, single limit and approval threshold', async () => {
    const g = createFakeGuardian({ policy });
    const result = async (amount: number, payee?: string) => g.handleCall(agent, 'af_propose_transfer', transfer(amount, payee));
    expect(await result(7500)).toMatchObject({ ok: true, result: { state: 'succeeded' } });
    expect(await result(7501)).toMatchObject({ ok: true, result: { state: 'pending_approval' } });
    expect(await result(10001)).toMatchObject({ ok: false, error: { code: 'SINGLE_LIMIT' } });
    expect(await result(100, 'attacker')).toMatchObject({ ok: false, error: { code: 'UNAPPROVED_PAYEE' } });
  });

  it('approves once, with the right digest and nonce', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    expect(await g.approve(p!.reservationId, 'sha256:' + '0'.repeat(64), p!.nonce)).toEqual({ ok: false, code: 'STALE_DIGEST' });
    expect(await g.approve(p!.reservationId, p!.digest, 'wrong')).toEqual({ ok: false, code: 'BAD_NONCE' });
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: true });
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code: 'NOT_PENDING' });
    expect(await g.listPending()).toEqual([]);
  });

  it('re-checks limits on approval and rejects if they now fail', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    await g.updatePolicy({ ...policy, transfers: { ...policy.transfers, maxSingleMinor: 8000 } }, 1);
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code: 'SINGLE_LIMIT' });
    expect(await g.listPending()).toEqual([]);
  });

  it('expires approvals after APPROVAL_TTL_SEC', async () => {
    const start = Date.UTC(2026, 9, 25);
    let now = start;
    const g = createFakeGuardian({ policy, nowMs: () => now });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    expect(p!.expiresAt).toBe(new Date(start + APPROVAL_TTL_SEC * 1000).toISOString());
    now = start + APPROVAL_TTL_SEC * 1000 - 1;
    expect(await g.listPending()).toHaveLength(1);
    now = start + APPROVAL_TTL_SEC * 1000;
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code: 'APPROVAL_EXPIRED' });
  });

  it('revoke denies new calls and rejects pending approvals', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    await g.revoke(agent);
    expect(await g.isRevoked(agent)).toBe(true);
    expect(await g.listPending()).toEqual([]);
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code: 'NOT_PENDING' });
    expect(await g.handleCall(agent, 'af_get_transfer_status', { transferRef: p!.reservationId })).toMatchObject({
      ok: false,
      error: { code: 'SESSION_REVOKED' },
    });
    // Issue #6: after revoke, an otherwise-allowed transfer gets SESSION_REVOKED.
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(100))).toMatchObject({
      ok: false,
      error: { code: 'SESSION_REVOKED' },
    });
    expect(await g.handleCall(agent, 'af_get_balance', { resourceId: policy.resourceId })).toMatchObject({
      ok: false,
      error: { code: 'SESSION_REVOKED' },
    });
  });

  it('rejects once, with the right nonce', async () => {
    const g = createFakeGuardian({ policy });
    const r = await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    expect(await g.reject(p!.reservationId, 'wrong')).toEqual({ ok: false, code: 'BAD_NONCE' });
    expect(await g.reject(p!.reservationId, p!.nonce)).toEqual({ ok: true });
    expect(await g.reject(p!.reservationId, p!.nonce)).toEqual({ ok: false, code: 'NOT_PENDING' });
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code: 'NOT_PENDING' });
    expect(await g.listPending()).toEqual([]);
    const ref = (r as { ok: true; result: { transferRef: string } }).result.transferRef;
    expect(await g.handleCall(agent, 'af_get_transfer_status', { transferRef: ref })).toMatchObject({
      ok: true,
      result: { state: 'REJECTED', reasonCode: null },
    });
    expect(await g.listActivity({ events: ['approval.rejected', 'transfer.succeeded'] })).toMatchObject([
      { event: 'approval.rejected', reservationId: ref },
    ]);
  });

  it('rejects an unknown reservation as NOT_PENDING', async () => {
    const g = createFakeGuardian({ policy });
    expect(await g.reject('tr_nope', 'x')).toEqual({ ok: false, code: 'NOT_PENDING' });
    expect(await g.approve('tr_nope', 'sha256:' + '0'.repeat(64), 'x')).toEqual({ ok: false, code: 'NOT_PENDING' });
  });

  it.each([
    ['transfers are disabled', { transfers: { ...policy.transfers, allow: false } }, 'CAPABILITY_DISABLED'],
    ['the payee was removed', { transfers: { ...policy.transfers, allowedPayeeIds: ['landlord'] } }, 'UNAPPROVED_PAYEE'],
    ['the resource changed', { resourceId: 'mock-bank:savings-01' }, 'UNKNOWN_ACTION'],
  ])('approval cannot override a hard deny: %s', async (_, change, code) => {
    const g = createFakeGuardian({ policy });
    const r = await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    expect(await g.updatePolicy({ ...policy, ...change }, 1)).toMatchObject({ ok: true });
    expect(await g.approve(p!.reservationId, p!.digest, p!.nonce)).toEqual({ ok: false, code });
    const ref = (r as { ok: true; result: { transferRef: string } }).result.transferRef;
    expect(await g.handleCall(agent, 'af_get_transfer_status', { transferRef: ref })).toMatchObject({
      ok: true,
      result: { state: 'REJECTED', reasonCode: code },
    });
    expect(await g.listActivity({ events: ['transfer.succeeded'] })).toEqual([]);
  });

  it('versions policy updates and rejects invalid ones', async () => {
    const g = createFakeGuardian({ policy });
    const tighter = { ...policy, transfers: { ...policy.transfers, maxSingleMinor: 5000 } };
    expect(await g.updatePolicy(tighter, 2)).toEqual({ ok: false, code: 'VERSION_CONFLICT' });
    expect(await g.updatePolicy({ ...tighter, extra: 1 }, 1)).toEqual({ ok: false, code: 'INVALID_POLICY' });
    expect(await g.updatePolicy(tighter, 1)).toEqual({ ok: true, version: 2 });
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(6000))).toMatchObject({
      ok: false,
      error: { code: 'SINGLE_LIMIT' },
    });
  });

  it('returns memos as untrusted text', async () => {
    const g = createFakeGuardian({ policy });
    const r = await g.handleCall(agent, 'af_list_transactions', { resourceId: policy.resourceId, fromDate: '2026-09-25', limit: 20 });
    expect(r.ok && (r.result as { transactions: { description: { trust: string } }[] }).transactions[0]?.description.trust).toBe(
      'external_untrusted',
    );
  });
});

describe('fake guardian: one agent', () => {
  it('denies calls for any agent but the policy one, and logs them', async () => {
    const g = createFakeGuardian({ policy });
    expect(await g.handleCall('other-agent', 'af_get_balance', { resourceId: policy.resourceId })).toEqual({
      ok: false,
      error: { code: 'UNKNOWN_ACTION', message: 'UNKNOWN_ACTION' },
    });
    expect(await g.handleCall('other-agent', 'af_propose_transfer', transfer(100))).toMatchObject({
      ok: false,
      error: { code: 'UNKNOWN_ACTION' },
    });
    const denied = await g.listActivity({ events: ['policy.denied'] });
    expect(denied.map((e) => [e.agent, e.reasonCode, e.metadata.unknownAgent])).toEqual([
      [agent, 'UNKNOWN_ACTION', 'other-agent'],
      [agent, 'UNKNOWN_ACTION', 'other-agent'],
    ]);
    expect(await g.listActivity({ events: ['read.executed', 'transfer.succeeded'] })).toEqual([]);
  });

  it.each([
    ['undefined', undefined, 'undefined'],
    ['a 1000-char string', 'x'.repeat(1000), 'x'.repeat(64)],
    ['an invalid agent id', 'Not An Agent!', 'Not An Agent!'],
  ])('logs a call from %s as a valid audit event', async (_, caller, recorded) => {
    const g = createFakeGuardian({ policy });
    const r = await g.handleCall(caller as unknown as string, 'af_get_balance', { resourceId: policy.resourceId });
    expect(r).toMatchObject({ ok: false, error: { code: 'UNKNOWN_ACTION' } });
    const events = await g.listActivity();
    expect(events).toHaveLength(1);
    expect(events.every((e) => AuditEvent.safeParse(e).success)).toBe(true);
    expect(events[0]).toMatchObject({ agent, event: 'policy.denied', metadata: { unknownAgent: recorded } });
  });

  it('ignores revoke for another agent', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    await g.revoke('other-agent');
    expect(await g.isRevoked('other-agent')).toBe(false);
    expect(await g.isRevoked(agent)).toBe(false);
    expect(await g.listPending()).toHaveLength(1);
    expect(await g.listActivity({ events: ['session.revoked'] })).toEqual([]);
  });

  it('refuses a policy update that would hand it to another agent', async () => {
    const g = createFakeGuardian({ policy });
    expect(await g.updatePolicy({ ...policy, agentId: 'other-agent' }, 1)).toEqual({ ok: false, code: 'INVALID_POLICY' });
    expect((await g.getPolicy()).policy.agentId).toBe(agent);
  });
});

describe('fake guardian: idempotency', () => {
  const ref = (r: unknown) => (r as { ok: true; result: { transferRef: string } }).result.transferRef;

  it('returns the same transfer for a retried key, without executing it again', async () => {
    const g = createFakeGuardian({ policy });
    const first = await g.handleCall(agent, 'af_propose_transfer', transfer(6000));
    const again = await g.handleCall(agent, 'af_propose_transfer', transfer(6000));
    expect(first).toMatchObject({ ok: true, result: { state: 'succeeded' } });
    expect(again).toEqual(first);
    expect(await g.listActivity({ events: ['transfer.succeeded'] })).toHaveLength(1);
  });

  it('denies a reused key with a different request as IDEMPOTENCY_CONFLICT, and logs it', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(6000));
    const changed = { ...transfer(6000), amountMinor: 6001 };
    expect(await g.handleCall(agent, 'af_propose_transfer', changed)).toEqual({
      ok: false,
      error: { code: 'IDEMPOTENCY_CONFLICT', message: 'IDEMPOTENCY_CONFLICT' },
    });
    expect((await g.listActivity({ events: ['policy.denied'] }))[0]).toMatchObject({ reasonCode: 'IDEMPOTENCY_CONFLICT' });
    expect(await g.listActivity({ events: ['transfer.succeeded'] })).toHaveLength(1);
  });

  it('returns the settled state when a pending transfer is retried after approval', async () => {
    const g = createFakeGuardian({ policy });
    const first = await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    expect(first).toMatchObject({ ok: true, result: { state: 'pending_approval' } });
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(9000))).toEqual(first);
    expect(await g.listPending()).toHaveLength(1);
    const [p] = await g.listPending();
    await g.approve(p!.reservationId, p!.digest, p!.nonce);
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(9000))).toEqual({
      ok: true,
      result: { state: 'succeeded', transferRef: ref(first), reasonCode: null },
    });
    expect(await g.listActivity({ events: ['transfer.succeeded'] })).toHaveLength(1);
  });

  it('reports a rejected or expired transfer as such, with its reason, on retry', async () => {
    let now = Date.UTC(2026, 9, 25);
    const g = createFakeGuardian({ policy, nowMs: () => now });
    const rejected = await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    await g.reject(p!.reservationId, p!.nonce);
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(9000))).toEqual({
      ok: true,
      result: { state: 'rejected', transferRef: ref(rejected), reasonCode: null },
    });
    const expired = await g.handleCall(agent, 'af_propose_transfer', transfer(9500));
    now += 16 * 60_000;
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(9500))).toEqual({
      ok: true,
      result: { state: 'expired', transferRef: ref(expired), reasonCode: 'APPROVAL_EXPIRED' },
    });
  });

  it('reports a transfer rejected at approval time with the rule that rejected it', async () => {
    const g = createFakeGuardian({ policy });
    const first = await g.handleCall(agent, 'af_propose_transfer', transfer(9000));
    const [p] = await g.listPending();
    await g.updatePolicy({ ...policy, transfers: { ...policy.transfers, maxSingleMinor: 8000 } }, 1);
    await g.approve(p!.reservationId, p!.digest, p!.nonce);
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(9000))).toEqual({
      ok: true,
      result: { state: 'rejected', transferRef: ref(first), reasonCode: 'SINGLE_LIMIT' },
    });
  });

  it('does not remember denied requests, so a fixed retry is evaluated afresh', async () => {
    const g = createFakeGuardian({ policy });
    const call = { ...transfer(6000), payeeId: 'landlord', idempotencyKey: 'retry-me-1' };
    await g.updatePolicy({ ...policy, transfers: { ...policy.transfers, allow: false } }, 1);
    expect(await g.handleCall(agent, 'af_propose_transfer', call)).toMatchObject({ ok: false, error: { code: 'CAPABILITY_DISABLED' } });
    await g.updatePolicy(policy, 2);
    expect(await g.handleCall(agent, 'af_propose_transfer', call)).toMatchObject({ ok: true, result: { state: 'succeeded' } });
  });
});

describe('fake guardian: reads', () => {
  const noReads = { ...policy, reads: { ...policy.reads, allow: false } };

  it('denies a balance read when reads are disabled', async () => {
    const g = createFakeGuardian({ policy: noReads });
    expect(await g.handleCall(agent, 'af_get_balance', { resourceId: policy.resourceId })).toMatchObject({
      ok: false,
      error: { code: 'CAPABILITY_DISABLED' },
    });
    expect(await g.listActivity({ events: ['read.executed'] })).toEqual([]);
  });

  it('denies a transaction list reaching further back than maxLookbackDays', async () => {
    // The mock bank's "today" is the fixture epoch, 2026-10-25.
    const g = createFakeGuardian({ policy: { ...policy, reads: { ...policy.reads, maxLookbackDays: 7 } } });
    const list = (fromDate: string) =>
      g.handleCall(agent, 'af_list_transactions', { resourceId: policy.resourceId, fromDate, limit: 20 });
    expect(await list('2026-10-18')).toMatchObject({ ok: true });
    expect(await list('2026-10-17')).toMatchObject({ ok: false, error: { code: 'INVALID_ARGUMENTS' } });
  });
});

describe('fake guardian: no live references out', () => {
  it('returns copies of the policy, pending approvals and activity', async () => {
    const g = createFakeGuardian({ policy });
    await g.handleCall(agent, 'af_propose_transfer', transfer(9000));

    const { policy: live } = await g.getPolicy();
    live.transfers.allowedPayeeIds.push('attacker');
    live.transfers.maxSingleMinor = 1_000_000;
    expect((await g.getPolicy()).policy).toEqual(policy);
    expect(await g.handleCall(agent, 'af_propose_transfer', transfer(100, 'attacker'))).toMatchObject({
      ok: false,
      error: { code: 'UNAPPROVED_PAYEE' },
    });

    const [p] = await g.listPending();
    p!.amountMinor = 1;
    expect((await g.listPending())[0]!.amountMinor).toBe(9000);

    const [e] = await g.listActivity();
    e!.metadata.forged = true;
    expect((await g.listActivity())[0]!.metadata).toEqual({});
  });

  it('does not keep a reference to the policy it was given', async () => {
    const mine = structuredClone(policy);
    const g = createFakeGuardian({ policy: mine });
    mine.transfers.allowedPayeeIds.push('attacker');
    const next = structuredClone(policy);
    await g.updatePolicy(next, 1);
    next.transfers.allowedPayeeIds.push('attacker');
    expect((await g.getPolicy()).policy.transfers.allowedPayeeIds).toEqual(policy.transfers.allowedPayeeIds);
  });
});

describe('fake guardian: listActivity limit', () => {
  it('defaults to 100 and caps at 1000', async () => {
    const g = createFakeGuardian({ policy });
    for (let i = 0; i < 1100; i++) await g.handleCall(agent, 'shell', {});
    expect(await g.listActivity()).toHaveLength(100);
    expect(await g.listActivity({ limit: 5 })).toHaveLength(5);
    expect(await g.listActivity({ limit: 5000 })).toHaveLength(1000);
  });

  it.each([0, -1, 1.5, Number.NaN, Infinity])('rejects limit %s', async (limit) => {
    const g = createFakeGuardian({ policy });
    await expect(g.listActivity({ limit })).rejects.toThrow(RangeError);
  });
});

describe('fake guardian: output contract', () => {
  it('every result matches TOOL_OUTPUTS', async () => {
    let now = Date.UTC(2026, 9, 25);
    const g = createFakeGuardian({ policy, nowMs: () => now });
    const calls: [ToolName, unknown][] = [
      ['af_get_balance', { resourceId: policy.resourceId }],
      ['af_list_transactions', { resourceId: policy.resourceId, fromDate: '2026-10-01', limit: 5 }],
      ['af_propose_transfer', transfer(6000)],
      ['af_propose_transfer', transfer(9000)],
      ['af_propose_transfer', transfer(9500)],
    ];
    const refs: string[] = [];
    for (const [tool, args] of calls) {
      const r = await g.handleCall(agent, tool, args);
      expect(r.ok && TOOL_OUTPUTS[tool].safeParse(r.result).success).toBe(true);
      if (r.ok && tool === 'af_propose_transfer') refs.push((r.result as { transferRef: string }).transferRef);
    }
    const [p] = await g.listPending();
    await g.reject(p!.reservationId, p!.nonce);
    now += APPROVAL_TTL_SEC * 1000;
    const states: unknown[] = [];
    for (const [tool, args] of [...calls.slice(2), ...refs.map((transferRef) => ['af_get_transfer_status', { transferRef }] as const)]) {
      const r = await g.handleCall(agent, tool, args);
      expect(r.ok && TOOL_OUTPUTS[tool].safeParse(r.result).success).toBe(true);
      if (r.ok) states.push((r.result as { state: unknown }).state);
    }
    expect(states).toEqual(['succeeded', 'rejected', 'expired', 'SUCCEEDED', 'REJECTED', 'EXPIRED']);
  });
});

describe('fake guardian: never rejects', () => {
  const throwing = {
    get resourceId(): string {
      throw new Error('boom');
    },
  };
  const proxy = new Proxy(
    {},
    {
      ownKeys() {
        throw new Error('boom');
      },
    },
  );
  const badId = {
    toString() {
      throw new Error('boom');
    },
  };

  it.each([
    ['a throwing getter', agent, throwing],
    ['a hostile Proxy', agent, proxy],
    ['an agent id that throws when stringified', badId, {}],
  ])('resolves INTERNAL_UNAVAILABLE for %s', async (_, caller, args) => {
    const g = createFakeGuardian({ policy });
    await expect(g.handleCall(caller as string, 'af_get_balance', args)).resolves.toEqual({
      ok: false,
      error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' },
    });
  });
});

describe('fake guardian: refused connections', () => {
  const refusal = { event: 'action.attempted', agent, tool: null, requestHash: null, reasonCode: null };

  it('logs one valid audit event per report, with the count', async () => {
    const g = createFakeGuardian({ policy });
    await g.recordRefusedConnection();
    await g.recordRefusedConnection(7);
    const events = await g.listActivity();
    expect(events.every((e) => AuditEvent.safeParse(e).success)).toBe(true);
    expect(events).toMatchObject([
      { ...refusal, metadata: { reason: 'connection_limit', refused: 7 } },
      { ...refusal, metadata: { reason: 'connection_limit', refused: 1 } },
    ]);
  });

  it.each([0, -3, 1.5, Number.NaN])('counts a nonsense refused count of %s as 1', async (n) => {
    const g = createFakeGuardian({ policy });
    await expect(g.recordRefusedConnection(n)).resolves.toBeUndefined();
    expect((await g.listActivity())[0]!.metadata).toEqual({ reason: 'connection_limit', refused: 1 });
  });
});

describe('fake guardian: recordRefusedConnection never rejects', () => {
  it('resolves even when logging fails', async () => {
    let broken = false;
    const g = createFakeGuardian({
      policy,
      nowMs: () => {
        if (broken) throw new Error('clock gone');
        return Date.UTC(2026, 9, 25);
      },
    });
    broken = true;
    await expect(g.recordRefusedConnection(3)).resolves.toBeUndefined();
  });
});

describe('fake guardian: recordOAuthEvent', () => {
  it('logs the app as the policy agent', async () => {
    const g = createFakeGuardian({ policy });
    await g.recordOAuthEvent('oauth.approved', { client: 'ChatGPT', redirectHost: 'chatgpt.com' });
    const events = await g.listActivity({ events: ['oauth.approved'] });
    expect(events).toHaveLength(1);
    expect(AuditEvent.safeParse(events[0]).success).toBe(true);
    expect(events[0]).toMatchObject({ agent, metadata: { client: 'ChatGPT', redirectHost: 'chatgpt.com' } });
  });

  it('cuts long values to 100 characters and strips control characters', async () => {
    const g = createFakeGuardian({ policy });
    await expect(g.recordOAuthEvent('oauth.denied', { client: 'x'.repeat(10_000), redirectHost: 'a\u0000b\u202ec.com' })).resolves.toBeUndefined();
    expect((await g.listActivity())[0]!.metadata).toEqual({ client: 'x'.repeat(100), redirectHost: 'abc.com' });
  });

  it('resolves even when logging fails', async () => {
    let broken = false;
    const g = createFakeGuardian({ policy, nowMs: () => { if (broken) throw new Error('clock gone'); return Date.UTC(2026, 9, 25); } });
    broken = true;
    await expect(g.recordOAuthEvent('oauth.revoked', { client: 'c', redirectHost: 'h' })).resolves.toBeUndefined();
  });
});
