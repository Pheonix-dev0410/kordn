import { createHash, randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it, vi } from 'vitest';
import { OAuthStore } from '../src/oauth/store.js';
import { createOAuthServer, OAUTH_PATHS, parsePublicUrl } from '../src/oauth/server.js';

const PUBLIC = 'https://x.example';
const REDIRECT = 'https://a.example/cb';

function setup(publicUrl = PUBLIC) {
  let time = 1_000_000;
  const store = new OAuthStore(new DatabaseSync(':memory:'), () => time);
  const audit = vi.fn();
  const server = createOAuthServer({ store, publicUrl: parsePublicUrl(publicUrl) as URL, ownerToken: 'owner', audit, now: () => time });
  const call = async (path: string, init?: RequestInit) => (await server.fetch(new Request(`${PUBLIC}${path}`, init))) as Response;
  const post = (path: string, body: Record<string, string>, headers: Record<string, string> = {}) =>
    call(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(body).toString() });
  const register = async (body: object = { redirect_uris: [REDIRECT], client_name: 'App' }) => {
    const res = await call('/register', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    return { res, body: (await res.json()) as Record<string, string> };
  };
  /** Registers a client, approves a request and returns what /token needs. */
  async function authorized(regBody: object = { redirect_uris: [REDIRECT] }) {
    const { body: reg } = await register(regBody);
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const approved = store.approve({ clientId: reg.client_id as string, redirectUri: REDIRECT, codeChallenge: challenge, resource: `${PUBLIC}/mcp`, state: null });
    if (!approved.ok) throw new Error('full');
    return { reg, verifier, code: approved.code, advance: (ms: number) => { time += ms; } };
  }
  const exchange = (a: { reg: Record<string, string>; verifier: string; code: string }, extra: Record<string, string> = {}) =>
    post('/token', { grant_type: 'authorization_code', client_id: a.reg.client_id as string, code: a.code, redirect_uri: REDIRECT, code_verifier: a.verifier, ...extra });
  return { server, store, audit, call, post, register, authorized, exchange, advance: (ms: number) => { time += ms; } };
}

describe('parsePublicUrl', () => {
  it('accepts origins', () => {
    expect(parsePublicUrl('https://x.example')?.href).toBe('https://x.example/');
    expect(parsePublicUrl('https://x.example/')?.origin).toBe('https://x.example');
    expect(parsePublicUrl('http://localhost:3333')?.origin).toBe('http://localhost:3333');
  });
  it('rejects everything else', () => {
    for (const bad of ['http://x.example', 'https://x.example/path', 'https://x.example?q', 'https://x.example/?', 'https://x.example#f', 'ftp://x', 'nope']) {
      expect(parsePublicUrl(bad), bad).toBeNull();
    }
  });
});

describe('metadata', () => {
  it('serves both protected-resource documents', async () => {
    const { call } = setup('https://x.example/');
    for (const path of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
      const res = await call(path);
      expect(res.headers.get('access-control-allow-origin')).toBe('*');
      expect(await res.json()).toMatchObject({ resource: `${PUBLIC}/mcp`, authorization_servers: [PUBLIC], resource_name: 'kordn' });
    }
  });
  it('serves authorization server metadata', async () => {
    const { call, server } = setup();
    expect(server.resourceMetadataUrl).toBe(`${PUBLIC}/.well-known/oauth-protected-resource/mcp`);
    expect(await (await call('/.well-known/oauth-authorization-server')).json()).toMatchObject({
      issuer: PUBLIC,
      authorization_endpoint: `${PUBLIC}/authorize`,
      token_endpoint: `${PUBLIC}/token`,
      registration_endpoint: `${PUBLIC}/register`,
      revocation_endpoint: `${PUBLIC}/revoke`,
      code_challenge_methods_supported: ['S256'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post', 'client_secret_basic'],
    });
  });
  it('works for a localhost http origin', async () => {
    const { server } = setup('http://localhost:3333');
    const res = (await server.fetch(new Request('http://localhost:3333/.well-known/oauth-protected-resource'))) as Response;
    expect((await res.json()).resource).toBe('http://localhost:3333/mcp');
  });
  it('falls through for other paths', async () => {
    const { server } = setup();
    expect(await server.fetch(new Request('http://x/mcp'))).toBeUndefined();
    expect(OAUTH_PATHS).toContain('/token');
  });
});

describe('/register', () => {
  it('returns RFC 7591 fields without auditing', async () => {
    const { register, audit } = setup();
    const { res, body } = await register({ redirect_uris: [REDIRECT], client_name: 'App', token_endpoint_auth_method: 'client_secret_post' });
    expect(res.status).toBe(201);
    expect(body).toMatchObject({
      client_name: 'App',
      redirect_uris: [REDIRECT],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'client_secret_post',
      client_secret_expires_at: 0,
    });
    expect(body.client_id).toBeTruthy();
    expect(body.client_secret).toBeTruthy();
    expect(body.client_id_issued_at).toBeTruthy();
    expect(audit).not.toHaveBeenCalled();
  });
  it('omits the secret for public clients', async () => {
    const { register } = setup();
    expect((await register()).body).not.toHaveProperty('client_secret');
  });
  it('rejects bad redirect URIs and content types', async () => {
    const { register, call } = setup();
    const bad = await register({ redirect_uris: ['http://evil/cb'] });
    expect(bad.res.status).toBe(400);
    expect(bad.body.error).toBe('invalid_redirect_uri');
    const text = await call('/register', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: '{}' });
    expect(text.status).toBe(400);
  });
  it('limits to 10 per minute', async () => {
    const { register, advance } = setup();
    for (let i = 0; i < 10; i++) expect((await register()).res.status).toBe(201);
    const limited = await register();
    expect(limited.res.status).toBe(429);
    expect(limited.body.error).toBe('temporarily_unavailable');
    advance(60_000);
    expect((await register()).res.status).toBe(201);
  });
  it('rejects GET', async () => {
    expect((await setup().call('/register')).status).toBe(405);
  });
});

describe('/token', () => {
  it('runs the code flow and refresh rotation', async () => {
    const { authorized, exchange, post, server } = setup();
    const a = await authorized();
    const res = await exchange(a);
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toBe('no-store');
    const body = (await res.json()) as Record<string, unknown>;
    expect(Object.keys(body).sort()).toEqual(['access_token', 'expires_in', 'refresh_token', 'token_type']);
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 3600 });
    const info = await server.verifier.verifyAccessToken(body.access_token as string);
    expect(info).toMatchObject({ clientId: a.reg.client_id, scopes: [] });
    expect(info.resource?.href).toBe(`${PUBLIC}/mcp`);
    const next = await post('/token', { grant_type: 'refresh_token', client_id: a.reg.client_id as string, refresh_token: body.refresh_token as string });
    expect(next.status).toBe(200);
  });
  it('requires a valid code_verifier', async () => {
    const { authorized, exchange } = setup();
    const a = await authorized();
    const missing = await exchange({ ...a, verifier: '' });
    expect(missing.status).toBe(400);
    expect((await missing.json()).error).toBe('invalid_request');
    const wrong = await exchange({ ...a, verifier: 'a'.repeat(43) });
    expect((await wrong.json()).error).toBe('invalid_grant');
  });
  it('treats code reuse as grant revocation', async () => {
    const { authorized, exchange, server } = setup();
    const a = await authorized();
    const first = (await (await exchange(a)).json()) as { access_token: string };
    const again = await exchange(a);
    expect(again.status).toBe(400);
    expect((await again.json()).error).toBe('invalid_grant');
    await expect(server.verifier.verifyAccessToken(first.access_token)).rejects.toMatchObject({ code: 'invalid_token' });
  });
  it('checks the resource', async () => {
    const { authorized, exchange } = setup();
    const a = await authorized();
    const other = await exchange(a, { resource: 'https://other/mcp' });
    expect((await other.json()).error).toBe('invalid_target');
    expect((await exchange(a, { resource: `${PUBLIC}/mcp/` })).status).toBe(200);
  });
  it('enforces the client auth method', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' });
    const body = { grant_type: 'authorization_code', client_id: a.reg.client_id as string, code: a.code, redirect_uri: REDIRECT, code_verifier: a.verifier };
    const none = await post('/token', body);
    expect(none.status).toBe(401);
    expect((await none.json()).error).toBe('invalid_client');
    const wrong = await post('/token', body, { authorization: `Basic ${Buffer.from(`${a.reg.client_id}:nope`).toString('base64')}` });
    expect(wrong.status).toBe(401);
    const ok = await post('/token', body, { authorization: `Basic ${Buffer.from(`${a.reg.client_id}:${a.reg.client_secret}`).toString('base64')}` });
    expect(ok.status).toBe(200);
  });
  it('accepts client_secret_post', async () => {
    const { authorized, exchange } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_post' });
    expect((await exchange(a)).status).toBe(401);
    expect((await exchange(a, { client_secret: a.reg.client_secret as string })).status).toBe(200);
  });
  it('detects refresh-token replay and audits it once', async () => {
    const { authorized, exchange, post, audit } = setup();
    const a = await authorized();
    const first = (await (await exchange(a)).json()) as { refresh_token: string };
    const refresh = () => post('/token', { grant_type: 'refresh_token', client_id: a.reg.client_id as string, refresh_token: first.refresh_token });
    expect((await refresh()).status).toBe(200);
    const replay = await refresh();
    expect(replay.status).toBe(400);
    expect((await replay.json()).error).toBe('invalid_grant');
    expect(audit).toHaveBeenCalledTimes(1);
    expect(audit).toHaveBeenCalledWith('oauth.refresh_reused', { client: 'Unnamed app', redirectHost: 'a.example' });
  });
  it('rejects other grant types and content types', async () => {
    const { authorized, post, call } = setup();
    const a = await authorized();
    const res = await post('/token', { grant_type: 'password', client_id: a.reg.client_id as string });
    expect((await res.json()).error).toBe('unsupported_grant_type');
    const json = await call('/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
    expect(json.status).toBe(400);
  });
});

describe('/revoke', () => {
  it('revokes an access token', async () => {
    const { authorized, exchange, post, server } = setup();
    const a = await authorized();
    const t = (await (await exchange(a)).json()) as { access_token: string };
    const res = await post('/revoke', { token: t.access_token, client_id: a.reg.client_id as string });
    expect(res.status).toBe(200);
    expect(await res.text()).toBe('');
    await expect(server.verifier.verifyAccessToken(t.access_token)).rejects.toThrow();
  });
  it('is a no-op for unknown tokens but still authenticates', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_post' });
    expect((await post('/revoke', { token: 'nope', client_id: a.reg.client_id as string, client_secret: a.reg.client_secret as string })).status).toBe(200);
    expect((await post('/revoke', { token: 'nope', client_id: a.reg.client_id as string })).status).toBe(401);
  });
});

describe('CORS', () => {
  it('answers preflight', async () => {
    const res = await setup().call('/token', { method: 'OPTIONS' });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
    expect(res.headers.get('access-control-allow-methods')).toBe('GET, POST, OPTIONS');
    expect(res.headers.get('access-control-allow-headers')).toBe('authorization, content-type, mcp-protocol-version');
  });
});
