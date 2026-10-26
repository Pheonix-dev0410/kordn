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
