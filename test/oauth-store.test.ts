import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it } from 'vitest';
import type { ClientRegistration } from '../src/oauth/client-metadata.js';
import { OAuthStore } from '../src/oauth/store.js';

const reg = (over: Partial<ClientRegistration> = {}): ClientRegistration => ({
  name: 'App',
  redirectUris: ['https://a.example/cb'],
  authMethod: 'none',
  ...over,
});

describe('OAuthStore clients', () => {
  let time = 1_000_000;
  const db = new DatabaseSync(':memory:');
  const store = new OAuthStore(db, () => time);

  it('registers and round-trips a client', () => {
    const { client, secret } = store.registerClient(reg());
    expect(client.id.length).toBeGreaterThanOrEqual(32);
    expect(secret).toBeNull();
    expect(store.getClient(client.id)).toEqual(client);
    expect(client).toMatchObject({ name: 'App', redirectUris: ['https://a.example/cb'], authMethod: 'none', createdAt: time, approvedAt: null });
    expect(store.getClient('nope')).toBeNull();
  });

  it('checks secrets', () => {
    const none = store.registerClient(reg()).client;
    expect(store.checkClientSecret(none.id, null)).toBe(true);
    expect(store.checkClientSecret(none.id, 'x')).toBe(false);
    for (const authMethod of ['client_secret_post', 'client_secret_basic'] as const) {
      const { client, secret } = store.registerClient(reg({ authMethod }));
      expect(secret).toBeTruthy();
      expect(store.checkClientSecret(client.id, secret)).toBe(true);
      expect(store.checkClientSecret(client.id, 'wrong')).toBe(false);
      expect(store.checkClientSecret(client.id, null)).toBe(false);
    }
    expect(store.checkClientSecret('missing', null)).toBe(false);
  });

  it('stores only a hash of the secret', () => {
    const { client, secret } = store.registerClient(reg({ authMethod: 'client_secret_post' }));
    const rows = db.prepare('SELECT * FROM oauth_clients WHERE id = ?').all(client.id);
    expect(JSON.stringify(rows)).not.toContain(secret as string);
  });
});

describe('OAuthStore unapproved pool', () => {
  const setup = () => {
    const t = { now: 1_000_000 };
    const db = new DatabaseSync(':memory:');
    return { t, db, store: new OAuthStore(db, () => t.now) };
  };

  it('keeps 50 unapproved clients and evicts the oldest', () => {
    const { t, db, store } = setup();
    const ids: string[] = [];
    for (let i = 0; i < 51; i++) {
      ids.push(store.registerClient(reg()).client.id);
      t.now += 1;
    }
    expect(db.prepare('SELECT COUNT(*) AS n FROM oauth_clients').get()).toEqual({ n: 50 });
    expect(store.getClient(ids[0])).toBeNull();
    expect(store.getClient(ids[1])).not.toBeNull();
  });

  it('prunes unapproved clients older than an hour', () => {
    const { t, store } = setup();
    const old = store.registerClient(reg()).client.id;
    t.now += 3_600_000;
    expect(store.getClient(old)).not.toBeNull();
    t.now += 1_000;
    store.registerClient(reg());
    expect(store.getClient(old)).toBeNull();
  });

  it('never evicts or prunes approved clients', () => {
    const { t, db, store } = setup();
    const approved = store.registerClient(reg()).client.id;
    db.prepare('UPDATE oauth_clients SET approved_at = ? WHERE id = ?').run(t.now, approved);
    t.now += 10 * 3_600_000;
    for (let i = 0; i < 60; i++) {
      store.registerClient(reg());
      t.now += 1;
    }
    expect(store.getClient(approved)).toMatchObject({ approvedAt: expect.any(Number) });
    expect(db.prepare('SELECT COUNT(*) AS n FROM oauth_clients').get()).toEqual({ n: 51 });
  });
});

describe('OAuthStore restart', () => {
  let dir = '';
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it('keeps clients across close and reopen', () => {
    dir = mkdtempSync(join(tmpdir(), 'kordn-oauth-'));
    const path = join(dir, 'oauth.db');
    const first = OAuthStore.open(path);
    const { client, secret } = first.registerClient(reg({ authMethod: 'client_secret_basic' }));
    first.close();
    const second = OAuthStore.open(path);
    expect(second.getClient(client.id)).toEqual(client);
    expect(second.checkClientSecret(client.id, secret)).toBe(true);
    second.close();
  });
});

describe('OAuthStore requests, codes and tokens', () => {
  const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
  const challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
  const resource = 'https://kordn.example/mcp';
  const setup = () => {
    const t = { now: 1_700_000_000_000 };
    const db = new DatabaseSync(':memory:');
    const store = new OAuthStore(db, () => t.now);
    const client = store.registerClient(reg({ name: 'ChatGPT', redirectUris: ['https://chatgpt.com/cb'] })).client;
    const req = (c = client) => ({ clientId: c.id, redirectUri: 'https://chatgpt.com/cb', codeChallenge: challenge, resource, state: 's1' });
    const issue = (c = client) => {
      const approved = store.approve(req(c));
      if (!approved.ok) throw new Error('full');
      const out = store.exchangeCode({ code: approved.code, clientId: c.id, redirectUri: 'https://chatgpt.com/cb', verifier, resource });
      if (!out.ok) throw new Error('exchange');
      return out.tokens;
    };
    return { t, db, store, client, req, issue };
  };

  it('takes a saved request once, with the right CSRF, before it expires', () => {
    const { t, store, req } = setup();
    const { id, csrf } = store.saveRequest(req());
    expect(store.takeRequest(id, 'wrong')).toBeNull();
    expect(store.takeRequest(id, csrf)).toEqual(req());
    expect(store.takeRequest(id, csrf)).toBeNull();
    const late = store.saveRequest(req());
    t.now += 601_000;
    expect(store.takeRequest(late.id, late.csrf)).toBeNull();
    const edge = store.saveRequest(req());
    t.now += 599_000;
    expect(store.takeRequest(edge.id, edge.csrf)).toEqual(req());
  });

  it('exchanges a code once and kills the grant on reuse', () => {
    const { store, client, req } = setup();
    const approved = store.approve(req());
    if (!approved.ok) throw new Error('full');
    const input = { code: approved.code, clientId: client.id, redirectUri: 'https://chatgpt.com/cb', verifier, resource };
    const first = store.exchangeCode(input);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    expect(store.verifyAccess(first.tokens.accessToken)).not.toBeNull();
    expect(store.exchangeCode(input)).toEqual({ ok: false, error: 'invalid_grant' });
    expect(store.verifyAccess(first.tokens.accessToken)).toBeNull();
    expect(store.refresh({ refreshToken: first.tokens.refreshToken, clientId: client.id, resource })).toMatchObject({ ok: false });
  });

  it('rejects a code after 60 s', () => {
    const { t, store, client, req } = setup();
    const approved = store.approve(req());
    if (!approved.ok) throw new Error('full');
    t.now += 61_000;
    expect(store.exchangeCode({ code: approved.code, clientId: client.id, redirectUri: 'https://chatgpt.com/cb', verifier, resource }))
      .toEqual({ ok: false, error: 'invalid_grant' });
  });

  it('rejects mismatched redirect, client, resource, verifier and unknown codes', () => {
    const { store, client, req } = setup();
    const other = store.registerClient(reg()).client;
    const good = { clientId: client.id, redirectUri: 'https://chatgpt.com/cb', verifier, resource };
    const bad: Array<Partial<typeof good>> = [
      { redirectUri: 'https://chatgpt.com/cb2' },
      { clientId: other.id },
      { resource: 'https://kordn.example/other' },
      { verifier: 'x'.repeat(43) },
      { verifier: 'short' },
    ];
    for (const over of bad) {
      const approved = store.approve(req());
      if (!approved.ok) throw new Error('full');
      expect(store.exchangeCode({ ...good, ...over, code: approved.code })).toEqual({ ok: false, error: 'invalid_grant' });
    }
    expect(store.exchangeCode({ ...good, code: 'nope' })).toEqual({ ok: false, error: 'invalid_grant' });
  });

  it('caps approved clients at 20 but lets approved ones re-approve', () => {
    const { store, req, client } = setup();
    const clients = [client];
    for (let i = 1; i < 21; i++) clients.push(store.registerClient(reg()).client);
    for (let i = 0; i < 20; i++) expect(store.approve(req(clients[i]))).toMatchObject({ ok: true });
    expect(store.approve(req(clients[20]))).toEqual({ ok: false, error: 'full' });
    expect(store.approve(req(clients[0]))).toMatchObject({ ok: true });
    expect(store.getClient(clients[20].id)?.approvedAt).toBeNull();
  });

  it('verifies access tokens and expires or revokes them', () => {
    const { t, store, client, issue } = setup();
    const a = issue();
    expect(a.expiresIn).toBe(3600);
    expect(store.verifyAccess(a.accessToken)).toEqual({ clientId: client.id, resource, expiresAt: Math.floor(t.now / 1000) + 3600 });
    expect(store.verifyAccess('nope')).toBeNull();
    expect(store.verifyAccess(a.refreshToken)).toBeNull();
    t.now += 3_601_000;
    expect(store.verifyAccess(a.accessToken)).toBeNull();

    const b = issue();
    store.revokeToken(b.accessToken, 'someone-else');
    expect(store.verifyAccess(b.accessToken)).not.toBeNull();
    store.revokeToken(b.accessToken, client.id);
    expect(store.verifyAccess(b.accessToken)).toBeNull();

    const c = issue();
    store.revokeToken(c.refreshToken, client.id);
    expect(store.verifyAccess(c.accessToken)).toBeNull();
    store.revokeToken('unknown', client.id);

    const d = issue();
    expect(store.revokeClient(client.id)).toMatchObject({ id: client.id });
    expect(store.verifyAccess(d.accessToken)).toBeNull();
    expect(store.getClient(client.id)).toBeNull();
    expect(store.revokeClient(client.id)).toBeNull();
  });

  it('rotates refresh tokens and kills the grant when an old one is replayed', () => {
    const { store, client, issue } = setup();
    const first = issue();
    const r = store.refresh({ refreshToken: first.refreshToken, clientId: client.id, resource });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.tokens.refreshToken).not.toBe(first.refreshToken);
    expect(store.verifyAccess(first.accessToken)).not.toBeNull();
    expect(store.verifyAccess(r.tokens.accessToken)).not.toBeNull();
    expect(store.refresh({ refreshToken: first.refreshToken, clientId: client.id, resource }))
      .toEqual({ ok: false, error: 'invalid_grant', reused: store.getClient(client.id) });
    expect(store.verifyAccess(r.tokens.accessToken)).toBeNull();
    expect(store.refresh({ refreshToken: r.tokens.refreshToken, clientId: client.id, resource })).toMatchObject({ ok: false, error: 'invalid_grant' });
  });

  it('refuses refresh for the wrong client or resource, and for unknown clients', () => {
    const { store, client, issue } = setup();
    const other = store.registerClient(reg()).client;
    const tokens = issue();
    expect(store.refresh({ refreshToken: tokens.refreshToken, clientId: other.id, resource })).toEqual({ ok: false, error: 'invalid_grant' });
    expect(store.refresh({ refreshToken: tokens.refreshToken, clientId: client.id, resource: 'https://x/mcp' })).toEqual({ ok: false, error: 'invalid_grant' });
    expect(store.refresh({ refreshToken: tokens.refreshToken, clientId: 'ghost', resource })).toEqual({ ok: false, error: 'invalid_client' });
    expect(store.refresh({ refreshToken: 'nope', clientId: client.id, resource })).toEqual({ ok: false, error: 'invalid_grant' });
    expect(store.refresh({ refreshToken: tokens.refreshToken, clientId: client.id, resource }).ok).toBe(true);
  });

  it('expires refresh after 30 idle days, and access use counts as activity', () => {
    const { t, store, client, issue } = setup();
    const idle = issue();
    t.now += 30 * 86_400_000 + 1_000;
    expect(store.refresh({ refreshToken: idle.refreshToken, clientId: client.id, resource })).toEqual({ ok: false, error: 'invalid_grant' });

    const active = issue();
    t.now += 1_800_000;
    store.verifyAccess(active.accessToken);
    t.now += 30 * 86_400_000;
    expect(store.refresh({ refreshToken: active.refreshToken, clientId: client.id, resource }).ok).toBe(true);
  });

  it('lists apps with throttled last use', () => {
    const { t, store, client, issue } = setup();
    expect(store.listApps()).toEqual([]);
    const tokens = issue();
    const approvedAt = t.now;
    expect(store.listApps()).toEqual([{ clientId: client.id, name: 'ChatGPT', redirectHost: 'chatgpt.com', approvedAt, lastUsedAt: null }]);
    store.verifyAccess(tokens.accessToken);
    const first = t.now;
    expect(store.listApps()[0]?.lastUsedAt).toBe(first);
    t.now += 59_000;
    store.verifyAccess(tokens.accessToken);
    expect(store.listApps()[0]?.lastUsedAt).toBe(first);
    t.now += 1_000;
    store.verifyAccess(tokens.accessToken);
    expect(store.listApps()[0]?.lastUsedAt).toBe(t.now);
  });

  it('lists newest approval first', () => {
    const { t, store, client, issue } = setup();
    issue();
    t.now += 1000;
    const second = store.registerClient(reg({ name: 'Second' })).client;
    issue(second);
    expect(store.listApps().map((a) => a.clientId)).toEqual([second.id, client.id]);
  });

  it('stores only hashes', () => {
    const { db, issue } = setup();
    const tokens = issue();
    const dump = JSON.stringify([
      db.prepare('SELECT * FROM oauth_tokens').all(),
      db.prepare('SELECT * FROM oauth_codes').all(),
      db.prepare('SELECT * FROM oauth_requests').all(),
    ]);
    expect(dump).not.toContain(tokens.accessToken);
    expect(dump).not.toContain(tokens.refreshToken);
  });

  it('keeps tokens across close and reopen', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-oauth-'));
    try {
      const path = join(dir, 'oauth.db');
      const first = OAuthStore.open(path);
      const client = first.registerClient(reg()).client;
      const approved = first.approve({ clientId: client.id, redirectUri: 'https://a.example/cb', codeChallenge: challenge, resource, state: null });
      if (!approved.ok) throw new Error('full');
      const out = first.exchangeCode({ code: approved.code, clientId: client.id, redirectUri: 'https://a.example/cb', verifier, resource });
      if (!out.ok) throw new Error('exchange');
      first.close();
      const second = OAuthStore.open(path);
      expect(second.verifyAccess(out.tokens.accessToken)).toMatchObject({ clientId: client.id, resource });
      second.close();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
