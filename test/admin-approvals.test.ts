import { afterEach, describe, expect, it } from 'vitest';
import type { AdminServer } from '../src/admin/server.js';
import { createFakeGuardian } from './fake-guardian.js';
import type { ActivityFilter, Guardian, PendingApproval } from '../src/guardian-api.js';
import type { AuditEvent } from '../src/schema.js';
import { agent, login, originOf, policy, send, start } from './admin-helpers.js';

const servers: AdminServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function started(...args: Parameters<typeof start>) {
  const result = await start(...args);
  servers.push(result.server);
  return result;
}

const HOSTILE = '<img src=x onerror=alert(1)>';
const ESCAPED = '&lt;img src=x onerror=alert(1)&gt;';

let key = 0;
const propose = (g: Guardian, amountMinor: number, payeeId = 'utilities') =>
  g.handleCall(agent, 'af_propose_transfer', {
    resourceId: policy.resourceId,
    payeeId,
    amountMinor,
    currency: 'USD',
    idempotencyKey: `admin-test-${++key}`,
  });

async function onePending(g: Guardian): Promise<PendingApproval> {
  await propose(g, 9000);
  const [p] = await g.listPending();
  return p!;
}

const approveForm = (p: PendingApproval) => ({ reservationId: p.reservationId, digest: p.digest, nonce: p.nonce });
const rejectForm = (p: PendingApproval) => ({ reservationId: p.reservationId, nonce: p.nonce });

function event(fields: Partial<AuditEvent>): AuditEvent {
  return {
    timestamp: '2026-10-25T12:00:00.000Z',
    event: 'policy.allowed',
    agent,
    tool: 'af_propose_transfer',
    requestHash: null,
    policyVersion: 1,
    reasonCode: null,
    reservationId: null,
    metadata: {},
    prevHash: null,
    ...fields,
  };
}

describe('admin approvals', () => {
  it('lists pending transfers from the guardian with forms bound to reservation, digest and nonce', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    const page = (await s.get('/approvals')).body;
    expect(page).toContain('utilities');
    expect(page).toContain('$90.00');
    expect(page).toContain(p.expiresAt);
    expect(page).toMatch(/Policy version[^<]*<\/th>/);
    expect(page).toContain(`value="${p.reservationId}"`);
    expect(page).toContain(`name="digest" value="${p.digest}"`);
    expect(page).toContain(`name="nonce" value="${p.nonce}"`);
    expect(page).toContain('action="/approvals/approve"');
    expect(page).toContain('action="/approvals/reject"');
    expect((await s.get('/')).headers.location).toBe('/approvals');
  });

  it('approves once; a second submit fails visibly', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    const first = await s.post('/approvals/approve', approveForm(p));
    expect(first.status).toBe(303);
    expect(first.headers.location).toBe('/approvals');
    expect((await s.get('/approvals')).body).toContain(`Approved transfer ${p.reservationId}`);
    expect((await guardian.listActivity({ events: ['approval.granted'] })).length).toBe(1);

    const second = await s.post('/approvals/approve', approveForm(p));
    expect(second.status).toBe(409);
    expect(second.body).toContain('class="error"');
    expect(second.body).toContain('NOT_PENDING');
    expect((await guardian.listActivity({ events: ['approval.granted'] })).length).toBe(1);
  });

  it('rejects once; a second submit fails visibly', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    expect((await s.post('/approvals/reject', rejectForm(p))).status).toBe(303);
    expect((await s.get('/approvals')).body).toContain(`Rejected transfer ${p.reservationId}`);
    const second = await s.post('/approvals/reject', rejectForm(p));
    expect(second.status).toBe(409);
    expect(second.body).toContain('NOT_PENDING');
    expect(await guardian.listPending()).toEqual([]);
  });

  it('shows the guardian refusing a stale digest, and leaves the transfer pending', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    const res = await s.post('/approvals/approve', { ...approveForm(p), digest: `sha256:${'0'.repeat(64)}` });
    expect(res.status).toBe(409);
    expect(res.body).toContain('STALE_DIGEST');
    expect((await guardian.listPending()).map((x) => x.reservationId)).toEqual([p.reservationId]);
  });

  it('rejects malformed decision forms', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    expect((await s.post('/approvals/approve', { reservationId: p.reservationId, nonce: p.nonce })).status).toBe(400);
    expect((await s.post('/approvals/reject', { ...rejectForm(p), nonce: 'n'.repeat(1000) })).status).toBe(400);
    expect(await guardian.listPending()).toHaveLength(1);
  });

  it('needs CSRF and Origin to approve', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    const noCsrf = await send(server, 'POST', '/approvals/approve', {
      form: approveForm(p),
      headers: { cookie: s.cookie, origin: originOf(server) },
    });
    expect(noCsrf.status).toBe(403);
    expect((await s.post('/approvals/approve', approveForm(p), { origin: 'http://evil.example' })).status).toBe(403);
    expect(await guardian.listPending()).toHaveLength(1);
  });

  it('rate-limits approve and reject POSTs', async () => {
    let now = 5_000_000;
    const { server, guardian } = await started({ nowMs: () => now });
    const p = await onePending(guardian);
    const s = await login(server);
    const junk = { reservationId: 'tr_nope', digest: p.digest, nonce: 'nope' };
    for (let i = 0; i < 30; i++) expect((await s.post(i % 2 ? '/approvals/approve' : '/approvals/reject', junk)).status).toBe(409);
    const limited = await s.post('/approvals/approve', approveForm(p));
    expect(limited.status).toBe(429);
    expect(await guardian.listPending()).toHaveLength(1);
    now += 60_000;
    expect((await s.post('/approvals/approve', approveForm(p))).status).toBe(303);
  });

  it('shows a pending item with a bad amount as invalid, with no approve button', async () => {
    const fake = createFakeGuardian({ policy });
    const item = (id: string, amountMinor: number): PendingApproval => ({
      reservationId: `tr_${id}`,
      agentId: agent,
      resourceId: policy.resourceId,
      payeeId: 'utilities',
      amountMinor,
      currency: 'USD',
      policyVersion: 1,
      digest: `digest-${id}`,
      nonce: `nonce-${id}`,
      expiresAt: '2026-10-25T12:15:00.000Z',
    });
    const bad = [item('neg', -5), item('zero', 0), item('frac', 1.5), item('nan', Number.NaN), item('huge', 2 ** 53)];
    const pending = [...bad, item('good', 9000)];
    const { server } = await started({ guardian: { ...fake, listPending: async () => pending } });
    const s = await login(server);
    const page = (await s.get('/approvals')).body;
    for (const p of bad) {
      expect(page, p.reservationId).not.toContain(`name="digest" value="${p.digest}"`);
      // Reject still works, so the user can clear it.
      expect(page, p.reservationId).toContain(`name="nonce" value="${p.nonce}"`);
    }
    expect(page.match(/Invalid amount/g)).toHaveLength(bad.length);
    expect(page).not.toContain('-1.-5');
    expect(page).not.toContain('NaN');
    expect(page).toContain('name="digest" value="digest-good"');
    expect(page).toContain('$90.00');
  });

  it('renders hostile pending fields as literal text', async () => {
    const fake = createFakeGuardian({ policy });
    const hostile: PendingApproval = {
      reservationId: `tr_"><script>alert(1)</script>`,
      agentId: agent,
      resourceId: HOSTILE,
      payeeId: HOSTILE,
      amountMinor: 9000,
      currency: 'USD',
      policyVersion: 1,
      digest: `"><b>x</b>`,
      nonce: HOSTILE,
      expiresAt: HOSTILE,
    };
    const { server } = await started({ guardian: { ...fake, listPending: async () => [hostile] } });
    const s = await login(server);
    const page = (await s.get('/approvals')).body;
    expect(page).not.toContain('<img');
    expect(page).not.toContain('<script');
    expect(page).not.toContain('<b>x');
    expect(page).toContain(ESCAPED);
  });
});

describe('admin activity log', () => {
  it('filters allowed / denied / pending / succeeded / unknown by audit event', async () => {
    const fake = createFakeGuardian({ policy });
    const seen: (ActivityFilter | undefined)[] = [];
    const guardian: Guardian = {
      ...fake,
      listActivity: async (filter) => {
        seen.push(filter);
        return fake.listActivity(filter);
      },
    };
    const { server } = await started({ guardian });
    const s = await login(server);
    const expected = {
      allowed: ['policy.allowed'],
      denied: ['policy.denied'],
      pending: ['policy.require_approval'],
      succeeded: ['transfer.succeeded'],
      unknown: ['transfer.unknown'],
    };
    for (const [type, events] of Object.entries(expected)) {
      seen.length = 0;
      expect((await s.get(`/activity?type=${type}`)).status, type).toBe(200);
      expect(seen.at(-1)?.events, type).toEqual(events);
    }
    seen.length = 0;
    expect((await s.get('/activity')).status).toBe(200);
    expect(seen.at(-1)?.events).toBeUndefined();
    expect((await s.get('/activity?type=everything')).status).toBe(400);
    expect((await s.get('/activity?type=denied&type=allowed')).status).toBe(400);
  });

  it('shows timestamps, events and reason codes from the guardian', async () => {
    const { server, guardian } = await started();
    await propose(guardian, 100, 'attacker');
    await propose(guardian, 100);
    const s = await login(server);
    const denied = (await s.get('/activity?type=denied')).body;
    const [deniedEvent] = await guardian.listActivity({ events: ['policy.denied'] });
    expect(denied).toContain(deniedEvent!.timestamp);
    expect(denied).toContain('policy.denied');
    expect(denied).toContain('UNAPPROVED_PAYEE');
    expect(denied).not.toContain('transfer.succeeded');
    const all = (await s.get('/activity')).body;
    expect(all).toContain('transfer.succeeded');
    expect(all).toContain('UNAPPROVED_PAYEE');
  });

  it('renders a hostile memo in metadata as literal escaped text', async () => {
    const fake = createFakeGuardian({ policy });
    const hostile = event({
      event: 'policy.denied',
      reasonCode: 'UNAPPROVED_PAYEE',
      reservationId: HOSTILE,
      metadata: { memo: HOSTILE, [HOSTILE]: '"><script>alert(1)</script>' },
    });
    const { server } = await started({ guardian: { ...fake, listActivity: async () => [hostile] } });
    const s = await login(server);
    const res = await s.get('/activity');
    expect(res.status).toBe(200);
    expect(res.body).not.toContain('<img');
    expect(res.body).not.toContain('<script');
    expect(res.body).toContain(`memo=${ESCAPED}`);
    expect(res.body).toContain('&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(String(res.headers['content-security-policy'])).toContain("default-src 'none'");
  });
});

describe('admin emergency stop', () => {
  it('revokes the agent with one POST and shows the revoked state', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const before = await s.get('/stop');
    expect(before.body).toContain('action="/stop"');
    expect(before.body).toContain('Agent is running');
    expect((await s.get('/approvals')).body).not.toContain('Agent stopped');

    const res = await s.post('/stop');
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/stop');
    expect(await guardian.isRevoked(agent)).toBe(true);
    expect((await s.get('/stop')).body).toContain('Agent stopped');
    // The revoked state shows on every page, not just Stop.
    for (const path of ['/approvals', '/activity', '/policy']) expect((await s.get(path)).body, path).toContain('Agent stopped');
    expect(await propose(guardian, 100)).toMatchObject({ ok: false, error: { code: 'SESSION_REVOKED' } });
  });

  it('needs CSRF and Origin to stop, and GET never stops', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const noCsrf = await send(server, 'POST', '/stop', {
      form: {},
      headers: { cookie: s.cookie, origin: originOf(server) },
    });
    expect(noCsrf.status).toBe(403);
    expect((await s.post('/stop', {}, { origin: 'http://evil.example' })).status).toBe(403);
    expect((await s.get(`/stop?csrf=${s.csrf}`)).status).toBe(200);
    expect(await guardian.isRevoked(agent)).toBe(false);
  });

  it('after Stop, pending approvals cannot be approved (end to end over HTTP)', async () => {
    const { server, guardian } = await started();
    const p = await onePending(guardian);
    const s = await login(server);
    // The user had the approval form open before pressing Stop.
    expect((await s.get('/approvals')).body).toContain(`name="nonce" value="${p.nonce}"`);
    expect((await s.post('/stop')).status).toBe(303);

    const res = await s.post('/approvals/approve', approveForm(p));
    expect(res.status).toBe(409);
    expect(res.body).toContain('class="error"');
    expect(res.body).toContain('Agent stopped');
    expect((await s.get('/approvals')).body).not.toContain(p.nonce);
    expect(await guardian.listActivity({ events: ['approval.granted', 'transfer.succeeded'] })).toEqual([]);
  });

  it('refuses to approve while stopped even if the guardian would allow it', async () => {
    const fake = createFakeGuardian({ policy });
    let approveCalls = 0;
    const guardian: Guardian = {
      ...fake,
      isRevoked: async () => true,
      approve: async () => {
        approveCalls += 1;
        return { ok: true };
      },
    };
    const { server } = await started({ guardian });
    const s = await login(server);
    const res = await s.post('/approvals/approve', { reservationId: 'tr_x', digest: 'd', nonce: 'n' });
    expect(res.status).toBe(409);
    expect(res.body).toContain('SESSION_REVOKED');
    expect(approveCalls).toBe(0);
  });

  it('reports transfers with unknown outcomes without claiming rollback', async () => {
    const fake = createFakeGuardian({ policy });
    const unknown = event({ event: 'transfer.unknown', reservationId: 'tr_unknownunknown01' });
    const guardian: Guardian = {
      ...fake,
      listActivity: async (filter) => (filter?.events?.includes('transfer.unknown') ? [unknown] : fake.listActivity(filter)),
    };
    const { server } = await started({ guardian });
    const s = await login(server);
    const page = (await s.get('/stop')).body;
    expect(page).toContain('tr_unknownunknown01');
    expect(page).toContain('not rolled back');
    expect(page).toContain('href="/activity?type=unknown"');
  });
});
