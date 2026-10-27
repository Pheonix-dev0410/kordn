import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import type { AdminServer } from '../src/admin/server.js';
import { OAuthStore } from '../src/oauth/store.js';
import { login, start } from './admin-helpers.js';

const servers: AdminServer[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => s.close()));
});

const HOSTILE = '<img src=x onerror=alert(1)>';
const ESCAPED = '&lt;img src=x onerror=alert(1)&gt;';
const RESOURCE = 'https://kordn.example/mcp';
const REDIRECT = 'https://app.example:8443/cb';

function seed(name = HOSTILE) {
  const store = new OAuthStore(new DatabaseSync(':memory:'));
  const { client } = store.registerClient({ name, redirectUris: [REDIRECT], authMethod: 'none' }, 'https://kordn.example');
  const verifier = 'v'.repeat(64);
  const request = { clientId: client.id, redirectUri: REDIRECT, codeChallenge: createHash('sha256').update(verifier).digest('base64url'), resource: RESOURCE, state: null };
  const approved = store.approve(request);
  if (!approved.ok) throw new Error('approve failed');
  const exchanged = store.exchangeCode({ code: approved.code, clientId: client.id, redirectUri: REDIRECT, verifier, resource: RESOURCE });
  if (!exchanged.ok) throw new Error('exchange failed');
  return { store, client, accessToken: exchanged.tokens.accessToken };
}

async function started(apps?: OAuthStore) {
  const result = await start(
    apps ? { apps: { list: () => apps.listApps(), revoke: (id) => apps.revokeClient(id) } } : {},
  );
  servers.push(result.server);
  return result;
}

describe('connected apps', () => {
  it('lists an approved app with escaped name and redirect host', async () => {
    const { store } = seed();
    const { server } = await started(store);
    const page = await (await login(server)).get('/apps');
    expect(page.status).toBe(200);
    expect(page.body).toContain(ESCAPED);
    expect(page.body).not.toContain(HOSTILE);
    expect(page.body).toContain('app.example:8443');
    expect(page.body).toContain('<a href="/apps">Apps</a>');
  });

  it('revokes an app, audits it and kills its tokens', async () => {
    const { store, client, accessToken } = seed('Notes');
    const { server, guardian } = await started(store);
    const session = await login(server);
    expect(store.verifyAccess(accessToken)).not.toBeNull();
    const res = await session.post('/apps/revoke', { client: client.id });
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe('/apps');
    expect(store.listApps()).toEqual([]);
    expect(store.verifyAccess(accessToken)).toBeNull();
    const [event] = await guardian.listActivity({ events: ['oauth.revoked'] });
    expect(event?.metadata).toMatchObject({ client: 'Notes', redirectHost: 'app.example:8443' });
    const page = await session.get('/apps');
    expect(page.body).toContain('Revoked Notes. It has to be approved again to reconnect.');
    expect(page.body).not.toContain(client.id);
  });

  it('answers 409 for an unknown app', async () => {
    const { store } = seed();
    const { server } = await started(store);
    const res = await (await login(server)).post('/apps/revoke', { client: 'nope' });
    expect(res.status).toBe(409);
    expect(res.body).toContain('That app is already gone.');
  });

  it('refuses a bad CSRF token and an oversized client field', async () => {
    const { store, client, accessToken } = seed();
    const { server } = await started(store);
    const session = await login(server);
    expect((await session.post('/apps/revoke', { client: client.id, csrf: 'wrong' })).status).toBe(403);
    expect(store.verifyAccess(accessToken)).not.toBeNull();
    expect((await session.post('/apps/revoke', { client: 'x'.repeat(257) })).status).toBe(400);
  });

  it('has no /apps without apps', async () => {
    const { server } = await started();
    const session = await login(server);
    expect((await session.get('/apps')).status).toBe(404);
    expect((await session.post('/apps/revoke', { client: 'x' })).status).toBe(404);
    expect((await session.get('/policy')).body).not.toContain('href="/apps"');
  });
});
