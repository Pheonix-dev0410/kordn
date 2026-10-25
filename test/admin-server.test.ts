import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { startAdminServer, type AdminServer } from '../src/admin/server.js';
import { createFakeGuardian } from '../src/fake-guardian.js';
import { agent, login, originOf, policy, type Reply, send, start } from './admin-helpers.js';

const servers: AdminServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

async function started(...args: Parameters<typeof start>) {
  const result = await start(...args);
  servers.push(result.server);
  return result;
}

const form = (overrides: Record<string, string> = {}) => ({
  version: '1',
  readsPerHour: '5',
  transfersPerDay: '3',
  maxSingleUsd: '100.00',
  maxTotalUsd: '250.00',
  payees: 'utilities\nlandlord',
  approvalAboveUsd: '75.00',
  ...overrides,
});

function expectSecurityHeaders(res: Reply): void {
  const csp = String(res.headers['content-security-policy']);
  expect(csp).toContain("default-src 'none'");
  expect(csp).toContain("frame-ancestors 'none'");
  expect(csp).toContain("form-action 'self'");
  expect(csp).not.toContain('unsafe-inline');
  expect(csp).not.toContain('script-src');
  expect(res.headers['x-content-type-options']).toBe('nosniff');
  expect(res.headers['referrer-policy']).toBe('same-origin');
  expect(res.headers['cache-control']).toBe('no-store');
}

describe('admin server binding', () => {
  it('refuses any host but 127.0.0.1, before listening', async () => {
    const guardian = createFakeGuardian({ policy });
    for (const host of ['0.0.0.0', '::', '::1', '192.168.1.10', 'localhost', '']) {
      await expect(startAdminServer({ guardian, agentId: agent, mode: 'guard', host }), host).rejects.toThrow(/127\.0\.0\.1/);
    }
  });

  it('refuses an unknown mode or agent id', async () => {
    const guardian = createFakeGuardian({ policy });
    await expect(startAdminServer({ guardian, agentId: agent, mode: 'observe' as 'guard' })).rejects.toThrow(/mode/);
    await expect(startAdminServer({ guardian, agentId: '<x>', mode: 'guard' })).rejects.toThrow(/agent/);
  });

  it('listens on 127.0.0.1 with a fresh token of at least 128 bits', async () => {
    const { server: a } = await started();
    const { server: b } = await started();
    expect(a.url).toMatch(/^http:\/\/127\.0\.0\.1:[0-9]+\/$/);
    expect(Buffer.from(a.token, 'base64url').length).toBeGreaterThanOrEqual(16);
    expect(a.token).not.toBe(b.token);
  });

  it('rejects requests whose Host is not the bound address (DNS rebinding)', async () => {
    const { server } = await started();
    const port = new URL(server.url).port;
    for (const host of [`localhost:${port}`, `evil.example:${port}`, '127.0.0.1', `127.0.0.1:${Number(port) + 1}`, `[::1]:${port}`]) {
      const res = await send(server, 'GET', '/login', { headers: { host } });
      expect(res.status, host).toBe(400);
      expectSecurityHeaders(res);
    }
    const s = await login(server);
    const res = await send(server, 'GET', '/policy', { headers: { cookie: s.cookie, host: `evil.example:${port}` } });
    expect(res.status).toBe(400);
    expect(res.body).not.toContain('utilities');
  });
});

describe('admin login and sessions', () => {
  it('sends the security headers on every response', async () => {
    const { server } = await started();
    expectSecurityHeaders(await send(server, 'GET', '/login'));
    expectSecurityHeaders(await send(server, 'GET', '/nope'));
    expectSecurityHeaders(await send(server, 'GET', '/policy'));
    const s = await login(server);
    expectSecurityHeaders(await s.get('/policy'));
    expectSecurityHeaders(await s.post('/policy', {}, { origin: 'http://evil.example' }));
  });

  it('allows the inline stylesheet by hash and nothing else inline', async () => {
    const { server } = await started();
    const res = await send(server, 'GET', '/login');
    const css = /<style>([\s\S]*?)<\/style>/.exec(res.body)![1]!;
    const hash = createHash('sha256').update(css).digest('base64');
    expect(String(res.headers['content-security-policy'])).toContain(`style-src 'sha256-${hash}'`);
    expect(res.body).not.toMatch(/<script|\sstyle=|\son[a-z]+=/i);
  });

  it('requires a session for everything but the login page', async () => {
    const { server } = await started();
    expect((await send(server, 'GET', '/login')).status).toBe(200);
    for (const path of ['/', '/policy']) {
      const res = await send(server, 'GET', path);
      expect(res.status, path).toBe(303);
      expect(res.headers.location).toBe('/login');
    }
    const res = await send(server, 'POST', '/policy', { form: form(), headers: { origin: originOf(server) } });
    expect(res.status).toBe(403);
    const bogus = await send(server, 'GET', '/policy', { headers: { cookie: 'kordn_admin=forged' } });
    expect(bogus.status).toBe(303);
  });

  it('logs in with the startup token and sets a strict session cookie', async () => {
    const { server } = await started();
    const bad = await send(server, 'POST', '/login', { form: { token: 'wrong' }, headers: { origin: originOf(server) } });
    expect(bad.status).toBe(401);
    expect(bad.headers['set-cookie']).toBeUndefined();

    const res = await send(server, 'POST', '/login', { form: { token: server.token }, headers: { origin: originOf(server) } });
    expect(res.status).toBe(303);
    const cookie = [res.headers['set-cookie']].flat()[0]!;
    expect(cookie).toMatch(/^kordn_admin=[A-Za-z0-9_-]{43};/);
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Strict');
    expect(cookie).toContain('Path=/');
    expect(cookie).toMatch(/Max-Age=[0-9]+/);
    expect(cookie).not.toContain(server.token);

    const a = await login(server);
    const b = await login(server);
    expect(a.cookie).not.toBe(b.cookie);
    expect(a.csrf).not.toBe(b.csrf);
    expect((await a.get('/policy')).status).toBe(200);
  });

  it('refuses a login from a foreign or missing Origin', async () => {
    const { server } = await started();
    for (const origin of ['http://evil.example', 'null', undefined]) {
      const headers: Record<string, string> = origin ? { origin } : {};
      const res = await send(server, 'POST', '/login', { form: { token: server.token }, headers });
      expect(res.status, origin).toBe(403);
      expect(res.headers['set-cookie']).toBeUndefined();
    }
  });

  it('rate-limits failed logins, then recovers after the window', async () => {
    let now = 1_000_000;
    const { server } = await started({ nowMs: () => now });
    const attempt = (token: string) =>
      send(server, 'POST', '/login', { form: { token }, headers: { origin: originOf(server) } });
    for (let i = 0; i < 5; i++) expect((await attempt('wrong')).status).toBe(401);
    expect((await attempt('wrong')).status).toBe(429);
    // Locked out: even the right token is refused until the window passes.
    expect((await attempt(server.token)).status).toBe(429);
    now += 61_000;
    expect((await attempt(server.token)).status).toBe(303);
  });

  it('expires sessions', async () => {
    let now = 1_000_000;
    const { server } = await started({ nowMs: () => now });
    const s = await login(server);
    expect((await s.get('/policy')).status).toBe(200);
    now += 8 * 3600_000 + 1;
    expect((await s.get('/policy')).status).toBe(303);
    expect((await s.post('/policy', form())).status).toBe(403);
  });

  it('logs out with a POST, ending the session', async () => {
    const { server } = await started();
    const s = await login(server);
    const res = await s.post('/logout');
    expect(res.status).toBe(303);
    expect([res.headers['set-cookie']].flat()[0]).toMatch(/^kordn_admin=;.*Max-Age=0/);
    expect((await s.get('/policy')).status).toBe(303);
  });
});

describe('admin CSRF and Origin checks', () => {
  it('rejects a change without a valid CSRF token with 403', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const other = await login(server);
    const origin = originOf(server);
    const attempts = [
      new URLSearchParams(form()),
      new URLSearchParams({ ...form(), csrf: '' }),
      new URLSearchParams({ ...form(), csrf: 'wrong' }),
      new URLSearchParams({ ...form(), csrf: other.csrf }),
      new URLSearchParams([...Object.entries(form()), ['csrf', s.csrf], ['csrf', 'wrong']]),
    ];
    for (const body of attempts) {
      const res = await send(server, 'POST', '/policy', { form: body, headers: { cookie: s.cookie, origin } });
      expect(res.status, body.toString()).toBe(403);
    }
    expect((await guardian.getPolicy()).version).toBe(1);
  });

  it('rejects a change from a foreign or missing Origin with 403, even with a valid CSRF token', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const port = Number(new URL(server.url).port);
    for (const origin of ['http://evil.example', `http://localhost:${port}`, `http://127.0.0.1:${port + 1}`, `https://127.0.0.1:${port}`, 'null']) {
      const res = await s.post('/policy', form({ maxSingleUsd: '1.00' }), { origin });
      expect(res.status, origin).toBe(403);
    }
    const missing = await send(server, 'POST', '/policy', {
      form: { ...form(), csrf: s.csrf },
      headers: { cookie: s.cookie },
    });
    expect(missing.status).toBe(403);
    expect((await guardian.getPolicy()).version).toBe(1);
  });

  it('never changes state on GET', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const query = new URLSearchParams({ ...form({ maxSingleUsd: '1.00' }), csrf: s.csrf });
    expect((await s.get(`/policy?${query}`)).status).toBe(200);
    expect((await s.get('/logout')).status).toBe(405);
    expect((await guardian.getPolicy()).version).toBe(1);
    expect((await s.get('/policy')).status).toBe(200);
  });

  it('accepts only small urlencoded form bodies', async () => {
    const { server } = await started();
    const s = await login(server);
    const json = await s.post('/policy', {}, { 'content-type': 'application/json' });
    expect(json.status).toBe(415);
    const big = await send(server, 'POST', '/policy', {
      body: `csrf=${s.csrf}&payees=${'a'.repeat(100_000)}`,
      headers: { cookie: s.cookie, origin: originOf(server), 'content-type': 'application/x-www-form-urlencoded' },
    });
    expect(big.status).toBe(413);
  });
});

describe('admin policy editor', () => {
  it('shows the current limits and the mode honestly', async () => {
    const { server } = await started();
    const s = await login(server);
    const page = (await s.get('/policy')).body;
    expect(page).toMatch(/name="readsPerHour"[^>]*value="5"/);
    expect(page).toMatch(/name="transfersPerDay"[^>]*value="3"/);
    expect(page).toMatch(/name="maxSingleUsd"[^>]*value="100.00"/);
    expect(page).toMatch(/name="maxTotalUsd"[^>]*value="250.00"/);
    expect(page).toMatch(/name="approvalAboveUsd"[^>]*value="75.00"/);
    expect(page).toMatch(/<textarea[^>]*name="payees"[^>]*>utilities\nlandlord<\/textarea>/);
    expect(page).toMatch(/name="version" value="1"/);
    expect(page).toContain('Guard mode');
    expect(page).toContain('mock-bank typed tools protected');
    expect(page).toContain('not protected');
    expect((await send(server, 'GET', '/login')).body).toContain('Guard mode');

    const { server: contained } = await started({ mode: 'contain' });
    expect((await send(contained, 'GET', '/login')).body).toContain('Contain mode');
  });

  it('saves limits as exact integer minor units through updatePolicy', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const res = await s.post(
      '/policy',
      form({
        readsPerHour: '7',
        transfersPerDay: '2',
        maxSingleUsd: '75.01',
        maxTotalUsd: '200.1',
        payees: ' utilities \r\nwater-co\n\n',
        approvalAboveUsd: '0.29',
      }),
    );
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/policy');
    const { policy: saved, version } = await guardian.getPolicy();
    expect(version).toBe(2);
    expect(saved.reads).toEqual({ ...policy.reads, maxCalls: 7, windowSec: 3600 });
    expect(saved.transfers).toEqual({
      ...policy.transfers,
      maxCalls: 2,
      windowSec: 86400,
      maxSingleMinor: 7501,
      maxCumulativeMinor: 20010,
      allowedPayeeIds: ['utilities', 'water-co'],
      humanApprovalAboveMinor: 29,
    });
    const page = (await s.get('/policy')).body;
    expect(page).toContain('Policy saved (version 2)');
    expect(page).toMatch(/name="maxSingleUsd"[^>]*value="75.01"/);
    expect((await s.get('/policy')).body).not.toContain('Policy saved');
  });

  it('rejects malformed amounts and counts without saving', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    for (const [field, value] of [
      ['maxSingleUsd', '1e3'],
      ['maxSingleUsd', '-5'],
      ['maxTotalUsd', '75.001'],
      ['approvalAboveUsd', ''],
      ['readsPerHour', '1.5'],
      ['transfersPerDay', '-1'],
      ['version', ''],
      ['version', '1.0'],
    ] as const) {
      const res = await s.post('/policy', form({ [field]: value }));
      expect(res.status, `${field}=${value}`).toBe(400);
      expect(res.body).toContain('class="error"');
      // The user's input is echoed back, escaped, so they can fix it.
      if (field !== 'version') expect(res.body).toContain(`value="${value}"`);
    }
    expect((await guardian.getPolicy()).version).toBe(1);
  });

  it('shows Policy validation errors', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    const tooHigh = await s.post('/policy', form({ maxSingleUsd: '300.00' }));
    expect(tooHigh.status).toBe(400);
    expect(tooHigh.body).toContain('maxSingleMinor must not exceed maxCumulativeMinor');
    const dup = await s.post('/policy', form({ payees: 'utilities\nutilities' }));
    expect(dup.status).toBe(400);
    expect(dup.body).toContain('duplicate payee id');
    const hostile = await s.post('/policy', form({ payees: '<img src=x onerror=alert(1)>' }));
    expect(hostile.status).toBe(400);
    expect(hostile.body).not.toContain('<img');
    expect(hostile.body).toContain('&lt;img src=x onerror=alert(1)&gt;');
    expect((await guardian.getPolicy()).version).toBe(1);
  });

  it('reports a version conflict instead of overwriting a newer policy', async () => {
    const { server, guardian } = await started();
    const s = await login(server);
    expect((await guardian.updatePolicy({ ...policy, reads: { ...policy.reads, maxCalls: 1 } }, 1)).ok).toBe(true);
    const res = await s.post('/policy', form({ version: '1' }));
    expect(res.status).toBe(409);
    expect(res.body).toContain('changed since you loaded it');
    expect((await guardian.getPolicy()).policy.reads.maxCalls).toBe(1);
  });

  it('escapes guardian-supplied policy text', async () => {
    const fake = createFakeGuardian({ policy });
    const guardian = {
      ...fake,
      getPolicy: async () => ({ policy: { ...policy, policyId: '<script>alert(1)</script>' }, version: 1 }),
    };
    const { server } = await started({ guardian });
    const s = await login(server);
    const page = (await s.get('/policy')).body;
    expect(page).not.toContain('<script');
    expect(page).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });

  it('fails closed with a generic error when the guardian throws', async () => {
    const fake = createFakeGuardian({ policy });
    const guardian = {
      ...fake,
      getPolicy: async () => {
        throw new Error('<b>db down</b>');
      },
    };
    const { server } = await started({ guardian });
    const s = await send(server, 'POST', '/login', { form: { token: server.token }, headers: { origin: originOf(server) } });
    const cookie = [s.headers['set-cookie']].flat()[0]!.split(';')[0]!;
    const res = await send(server, 'GET', '/policy', { headers: { cookie } });
    expect(res.status).toBe(503);
    expect(res.body).not.toContain('db down');
  });
});
