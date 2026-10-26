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
  it('answers other methods on the bare root document with 405', async () => {
    const res = await setup().call('/.well-known/oauth-protected-resource', { method: 'POST' });
    expect(res.status).toBe(405);
  });
  it('rejects a non-loopback http public URL', () => {
    const store = new OAuthStore(new DatabaseSync(':memory:'));
    const make = (url: string) => createOAuthServer({ store, publicUrl: new URL(url), ownerToken: 'o', audit: vi.fn() });
    expect(() => make('http://x.example')).toThrow();
    expect(() => make('http://127.0.0.1:1')).not.toThrow();
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

describe('client authentication', () => {
  const basic = (id: string, secret: string) => ({ authorization: `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}` });
  const grant = (a: { verifier: string; code: string }) =>
    ({ grant_type: 'authorization_code', code: a.code, redirect_uri: REDIRECT, code_verifier: a.verifier });

  it('rejects Basic with a different form client_id', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' });
    const res = await post('/token', { ...grant(a), client_id: 'other' }, basic(a.reg.client_id as string, a.reg.client_secret as string));
    expect(res.status).toBe(401);
  });
  it('accepts Basic with a matching form client_id', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' });
    const res = await post('/token', { ...grant(a), client_id: a.reg.client_id as string }, basic(a.reg.client_id as string, a.reg.client_secret as string));
    expect(res.status).toBe(200);
  });
  it('rejects a secret split across Basic and form', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_post' });
    const res = await post('/token', { ...grant(a), client_secret: a.reg.client_secret as string }, basic(a.reg.client_id as string, ''));
    expect(res.status).toBe(401);
    const both = await post('/token', { ...grant(a), client_secret: a.reg.client_secret as string }, basic(a.reg.client_id as string, a.reg.client_secret as string));
    expect(both.status).toBe(401);
  });
  it('rejects a none client presenting a secret', async () => {
    const { authorized, post } = setup();
    const a = await authorized();
    const viaBasic = await post('/token', grant(a), basic(a.reg.client_id as string, 'junk'));
    expect(viaBasic.status).toBe(401);
    const viaForm = await post('/token', { ...grant(a), client_id: a.reg.client_id as string, client_secret: 'junk' });
    expect(viaForm.status).toBe(401);
  });
  it('lets secret-method clients use either method', async () => {
    const { authorized, post } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_post' });
    const res = await post('/token', grant(a), basic(a.reg.client_id as string, a.reg.client_secret as string));
    expect(res.status).toBe(200);
    const b = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' });
    const res2 = await post('/token', { ...grant(b), client_id: b.reg.client_id as string, client_secret: b.reg.client_secret as string });
    expect(res2.status).toBe(200);
  });
  it('answers 401 for malformed Basic headers', async () => {
    const { authorized, post } = setup();
    const a = await authorized();
    for (const authorization of ['Basic !!!', 'Basic bm9jb2xvbg==', `Basic ${Buffer.from('%E0%A4%A:x').toString('base64')}`]) {
      const res = await post('/token', { ...grant(a), client_id: a.reg.client_id as string }, { authorization });
      expect(res.status, authorization).toBe(401);
    }
  });
});

describe('/revoke', () => {
  it('authenticates a client_secret_basic client', async () => {
    const { authorized, exchange, post, server } = setup();
    const a = await authorized({ redirect_uris: [REDIRECT], token_endpoint_auth_method: 'client_secret_basic' });
    const t = (await (await exchange(a, { client_secret: a.reg.client_secret as string })).json()) as { access_token: string };
    const h = { authorization: `Basic ${Buffer.from(`${a.reg.client_id}:${a.reg.client_secret}`).toString('base64')}` };
    expect((await post('/revoke', { token: t.access_token }, { authorization: 'Basic !!!' })).status).toBe(401);
    expect((await post('/revoke', { token: t.access_token }, h)).status).toBe(200);
    await expect(server.verifier.verifyAccessToken(t.access_token)).rejects.toThrow();
  });
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

describe('/authorize', () => {
  function flow(publicUrl = PUBLIC) {
    const s = setup(publicUrl);
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const query = (params: Record<string, string>) => `/authorize?${new URLSearchParams(params).toString()}`;
    const params = (clientId: string, redirectUri = REDIRECT, extra: Record<string, string> = {}) => ({
      response_type: 'code', client_id: clientId, redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256', state: 'st', ...extra,
    });
    /** GETs the consent page and returns the hidden fields. */
    async function open(clientId: string, redirectUri = REDIRECT) {
      const res = await s.call(query(params(clientId, redirectUri)));
      expect(res.status).toBe(200);
      return fields(await res.text());
    }
    const submit = (body: Record<string, string>, origin = PUBLIC) => s.post('/authorize', body, { origin });
    return { ...s, verifier, challenge, query, params, open, submit };
  }
  function fields(page: string) {
    const request = page.match(/name="request" value="([^"]+)"/)?.[1];
    const csrf = page.match(/name="csrf" value="([^"]+)"/)?.[1];
    if (!request || !csrf) throw new Error('no form');
    return { request, csrf };
  }
  const location = (res: Response) => new URL(res.headers.get('location') as string);

  it('shows an error page without redirecting for an unknown client or redirect_uri', async () => {
    const { call, query, params, register } = flow();
    const unknown = await call(query(params('nope')));
    expect(unknown.status).toBe(400);
    expect(unknown.headers.get('location')).toBeNull();
    const { body } = await register({ redirect_uris: ['https://app.example/cb?x=1'] });
    for (const uri of ['https://app.example/cb?x=1/', 'https://app.example/cb/?x=1', 'https://app.example/cb?x=2', 'https://app.example/cb']) {
      const res = await call(query(params(body.client_id as string, uri)));
      expect(res.status, uri).toBe(400);
      expect(res.headers.get('location'), uri).toBeNull();
      expect(res.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    }
  });
  it('redirects other request errors with state and iss', async () => {
    const { call, query, params, register } = flow();
    const id = (await register()).body.client_id as string;
    const cases: [Record<string, string>, string][] = [
      [{ response_type: 'token' }, 'unsupported_response_type'],
      [{ code_challenge: '' }, 'invalid_request'],
      [{ code_challenge: 'short' }, 'invalid_request'],
      [{ code_challenge_method: 'plain' }, 'invalid_request'],
      [{ code_challenge_method: '' }, 'invalid_request'],
      [{ resource: 'https://other.example/mcp' }, 'invalid_target'],
    ];
    for (const [extra, error] of cases) {
      const res = await call(query(params(id, REDIRECT, extra)));
      expect(res.status, error).toBe(303);
      const to = location(res);
      expect(to.origin + to.pathname).toBe(REDIRECT);
      expect(Object.fromEntries(to.searchParams)).toEqual({ error, state: 'st', iss: PUBLIC });
    }
    const p = params(id);
    const { code_challenge: _, ...missing } = p;
    const res = await call(query(missing));
    expect(location(res).searchParams.get('error')).toBe('invalid_request');
    expect((await call(query(params(id, REDIRECT, { resource: `${PUBLIC}/mcp/` })))).status).toBe(200);
  });
  it('sends the consent page with framing and referrer protection', async () => {
    const { call, query, params, register } = flow();
    const id = (await register({ redirect_uris: ['https://app.example/cb'] })).body.client_id as string;
    const res = await call(query(params(id, 'https://app.example/cb')));
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    expect(res.headers.get('referrer-policy')).toBe('same-origin');
    expect(res.headers.get('cache-control')).toBe('no-store');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
    const csp = res.headers.get('content-security-policy') as string;
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self' https://app.example");
    expect(await res.text()).toContain('app.example');
  });
  it('approves, keeping the redirect query, and the code exchanges', async () => {
    const { register, open, submit, post, verifier, audit } = flow();
    const redirect = 'https://app.example/cb?x=1';
    const id = (await register({ redirect_uris: [redirect], client_name: 'App' })).body.client_id as string;
    const res = await submit({ ...(await open(id, redirect)), owner_token: 'owner', decision: 'approve' });
    expect(res.status).toBe(303);
    expect(res.headers.get('x-frame-options')).toBe('DENY');
    const to = location(res);
    expect(to.origin + to.pathname).toBe('https://app.example/cb');
    expect(to.searchParams.get('x')).toBe('1');
    expect(to.searchParams.get('state')).toBe('st');
    expect(to.searchParams.get('iss')).toBe(PUBLIC);
    const code = to.searchParams.get('code') as string;
    expect(code).toBeTruthy();
    expect(audit).toHaveBeenCalledWith('oauth.approved', { client: 'App', redirectHost: 'app.example' });
    const tokens = await post('/token', { grant_type: 'authorization_code', client_id: id, code, redirect_uri: redirect, code_verifier: verifier });
    expect(tokens.status).toBe(200);
  });
  it('omits state when none was sent', async () => {
    const { call, query, params, register, submit } = flow();
    const id = (await register()).body.client_id as string;
    const { state: _, ...rest } = params(id);
    const page = fields(await (await call(query(rest))).text());
    const to = location(await submit({ ...page, owner_token: 'owner', decision: 'approve' }));
    expect(to.searchParams.has('state')).toBe(false);
    expect(to.searchParams.get('code')).toBeTruthy();
  });
  it('uses a request only once', async () => {
    const { register, open, submit, store, post, verifier } = flow();
    const id = (await register()).body.client_id as string;
    const form = { ...(await open(id)), owner_token: 'owner', decision: 'approve' };
    const first = await submit(form);
    expect(first.status).toBe(303);
    const second = await submit(form);
    expect(second.status).toBe(400);
    expect(second.headers.get('location')).toBeNull();
    expect(await second.text()).toContain('This approval page has expired or was already used. Start connecting again from the app.');
    const code = location(first).searchParams.get('code') as string;
    expect((await post('/token', { grant_type: 'authorization_code', client_id: id, code, redirect_uri: REDIRECT, code_verifier: verifier })).status).toBe(200);
    expect(store.listApps()).toHaveLength(1);
  });
  it('rejects a wrong CSRF token or an expired request', async () => {
    const { register, open, submit, advance } = flow();
    const id = (await register()).body.client_id as string;
    const page = await open(id);
    expect((await submit({ ...page, csrf: 'wrong', owner_token: 'owner', decision: 'approve' })).status).toBe(400);
    advance(600_000);
    expect((await submit({ ...page, owner_token: 'owner', decision: 'approve' })).status).toBe(400);
  });
  it('denies', async () => {
    const { register, open, submit, audit, store } = flow();
    const id = (await register({ redirect_uris: [REDIRECT], client_name: 'App' })).body.client_id as string;
    const res = await submit({ ...(await open(id)), decision: 'deny' });
    expect(res.status).toBe(303);
    expect(Object.fromEntries(location(res).searchParams)).toEqual({ error: 'access_denied', state: 'st', iss: PUBLIC });
    expect(audit).toHaveBeenCalledWith('oauth.denied', { client: 'App', redirectHost: 'a.example' });
    expect(store.listApps()).toHaveLength(0);
  });
  it('locks out wrong owner tokens but lets the right one through', async () => {
    const { register, open, submit, advance } = flow();
    const id = (await register()).body.client_id as string;
    let page = await open(id);
    const wrong = async () => {
      const res = await submit({ ...page, owner_token: 'nope', decision: 'approve' });
      const text = await res.text();
      page = fields(text);
      return { status: res.status, text };
    };
    for (let i = 0; i < 5; i++) {
      const res = await wrong();
      expect(res.status).toBe(401);
      expect(res.text).toContain('Wrong KORDN_TOKEN.');
    }
    const locked = await wrong();
    expect(locked.status).toBe(429);
    expect(locked.text).toContain('Too many wrong tokens. Wait a minute.');
    const right = await submit({ ...page, owner_token: 'owner', decision: 'approve' });
    expect(right.status).toBe(303);
    expect(location(right).searchParams.get('code')).toBeTruthy();
    page = await open(id);
    advance(61_000);
    expect((await wrong()).status).toBe(401);
  });
  it('requires the public origin on POST', async () => {
    const { register, open, submit } = flow();
    const id = (await register()).body.client_id as string;
    const page = await open(id);
    const res = await submit({ ...page, owner_token: 'owner', decision: 'approve' }, 'https://evil.example');
    expect(res.status).toBe(403);
    expect(res.headers.get('location')).toBeNull();
    expect((await submit({ ...page, owner_token: 'owner', decision: 'approve' })).status).toBe(303);
  });
  it('rejects non-form POSTs and other methods', async () => {
    const { call } = flow();
    const json = await call('/authorize', { method: 'POST', headers: { 'content-type': 'application/json', origin: PUBLIC }, body: '{}' });
    expect(json.status).toBe(400);
    const options = await call('/authorize', { method: 'OPTIONS' });
    expect(options.status).toBe(405);
    expect(options.headers.get('access-control-allow-origin')).toBeNull();
  });
  it('refuses when 20 apps are connected', async () => {
    const { register, open, submit, store, challenge } = flow();
    for (let i = 0; i < 20; i++) {
      // Straight to the store: /register allows only 10 a minute.
      const other = store.registerClient({ name: `App ${i}`, redirectUris: [REDIRECT], authMethod: 'none' }).client.id;
      expect(store.approve({ clientId: other, redirectUri: REDIRECT, codeChallenge: challenge, resource: `${PUBLIC}/mcp`, state: null }).ok).toBe(true);
    }
    const id = (await register()).body.client_id as string;
    const res = await submit({ ...(await open(id)), owner_token: 'owner', decision: 'approve' });
    expect(res.status).toBe(409);
    expect(await res.text()).toContain('kordn already has 20 connected apps. Revoke one in the admin UI first.');
  });
  it('shows an error page when the client went away while the page was open', async () => {
    const { register, open, submit, store } = flow();
    const id = (await register()).body.client_id as string;
    const page = await open(id);
    store.revokeClient(id);
    const res = await submit({ ...page, owner_token: 'owner', decision: 'approve' });
    expect(res.status).toBe(400);
    expect(res.headers.get('location')).toBeNull();
    expect(await res.text()).toContain('This app is no longer registered. Start connecting again from the app.');
  });
  it('escapes the client name', async () => {
    const { register, call, query, params } = flow();
    const id = (await register({ redirect_uris: [REDIRECT], client_name: '<img src=x onerror=alert(1)>' })).body.client_id as string;
    const text = await (await call(query(params(id)))).text();
    expect(text).not.toContain('<img');
    expect(text).toContain('&lt;img src=x onerror=alert(1)&gt;');
  });
});
