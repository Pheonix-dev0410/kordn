import { createHash, randomBytes } from 'node:crypto';
import { request } from 'node:http';
import { createServer, type AddressInfo } from 'node:net';
import { DatabaseSync } from 'node:sqlite';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { afterEach, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from './fake-guardian.js';
import { serveHttp } from '../src/http.js';
import { createMcpServer } from '../src/mcp-server.js';
import { createOAuthServer, parsePublicUrl } from '../src/oauth/server.js';
import { OAuthStore } from '../src/oauth/store.js';
import { Policy } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const TOKEN = 'test-token-0123456789abcdef0123456789';
const REDIRECT = 'http://localhost:9/cb';
const closers: (() => Promise<void>)[] = [];

afterEach(async () => {
  while (closers.length) await closers.pop()?.();
});

/** serveHttp needs the port before the OAuth server can be built, so take a free one first. */
async function freePort(): Promise<number> {
  const probe = createServer();
  await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

async function start(publicUrl?: string) {
  const port = await freePort();
  const pub = publicUrl ?? `http://localhost:${port}`;
  let offset = 0;
  // Real time plus an offset: the SDK compares expiresAt with Date.now() too.
  const now = () => Date.now() + offset;
  const store = new OAuthStore(new DatabaseSync(':memory:'), now);
  const oauth = createOAuthServer({ store, publicUrl: parsePublicUrl(pub) as URL, ownerToken: TOKEN, audit: () => {}, now });
  const guardian = createFakeGuardian({ policy });
  const handleCall = guardian.handleCall.bind(guardian);
  const http = await serveHttp({
    factory: () => createMcpServer({ agentId: policy.agentId, handleCall }),
    token: TOKEN,
    port,
    oauth,
  });
  closers.push(() => http.close());
  // Requests go to 127.0.0.1; the public URL only has to be what the OAuth server reports.
  const base = http.url.replace(/\/mcp$/, '');
  return { ...http, base, pub, port, store, oauth, advance: (ms: number) => void (offset += ms) };
}

/** Raw request so tests can set Host, which fetch won't let us override. */
function raw(
  url: string,
  init: { method?: string; headers?: Record<string, string>; body?: string } = {},
): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: init.method ?? 'GET', headers: init.headers ?? {} }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks).toString() }));
    });
    req.on('error', reject);
    req.end(init.body);
  });
}

/**
 * Stream up to `total` bytes as a chunked JSON POST, as fast as the server takes them. Resolves
 * with the response status and how much was written before the server cut the connection.
 */
function upload(url: string, total: number): Promise<{ status: number; written: number }> {
  return new Promise((resolve) => {
    let status = 0;
    let written = 0;
    const chunk = Buffer.alloc(64 * 1024, 'x');
    const req = request(url, { method: 'POST', headers: { 'content-type': 'application/json' } }, (res) => {
      status = res.statusCode ?? 0;
      res.resume();
    });
    const done = () => resolve({ status, written });
    req.on('error', done);
    req.on('close', done);
    const next = (): void => {
      if (req.destroyed) return;
      if (written >= total) return void req.end();
      written += chunk.length;
      if (req.write(chunk)) setImmediate(next);
      else req.once('drain', next);
    };
    next();
  });
}

const accept = { accept: 'application/json, text/event-stream' };
const listTools = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });

const mcpPost = (url: string, headers: Record<string, string> = {}) =>
  fetch(url, { method: 'POST', headers: { ...accept, 'content-type': 'application/json', ...headers }, body: listTools });

const form = (body: Record<string, string>) => ({
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams(body).toString(),
});

/** register → GET /authorize → approve on the consent page → /token, all over HTTP. */
async function connect(s: { base: string; pub: string }) {
  const reg = await fetch(`${s.base}/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ redirect_uris: [REDIRECT], client_name: 'Test app', token_endpoint_auth_method: 'none' }),
  });
  expect(reg.status).toBe(201);
  const clientId = ((await reg.json()) as { client_id: string }).client_id;

  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const query = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: 'st',
    resource: `${s.pub}/mcp`,
  });
  const consent = await fetch(`${s.base}/authorize?${query}`);
  expect(consent.status).toBe(200);
  const page = await consent.text();
  const field = (name: string) => new RegExp(`name="${name}" value="([^"]+)"`).exec(page)?.[1] as string;

  const decided = await fetch(`${s.base}/authorize`, {
    ...form({ request: field('request'), csrf: field('csrf'), owner_token: TOKEN, decision: 'approve' }),
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: s.pub },
    redirect: 'manual',
  });
  expect(decided.status).toBe(303);
  const back = new URL(decided.headers.get('location') as string);
  expect(back.origin + back.pathname).toBe(REDIRECT);
  // Built from the public URL, not from the address the request came in on.
  expect(back.searchParams.get('iss')).toBe(s.pub);

  const token = await fetch(`${s.base}/token`, form({
    grant_type: 'authorization_code',
    client_id: clientId,
    code: back.searchParams.get('code') as string,
    redirect_uri: REDIRECT,
    code_verifier: verifier,
  }));
  expect(token.status).toBe(200);
  return { clientId, access: ((await token.json()) as { access_token: string }).access_token };
}

async function expectChallenge(res: Response, pub: string) {
  expect(res.status).toBe(401);
  expect(res.headers.get('www-authenticate')).toContain(`resource_metadata="${pub}/.well-known/oauth-protected-resource/mcp"`);
  expect(await res.json()).toMatchObject({ error: 'invalid_token' });
}

describe('OAuth over HTTP', () => {
  it('challenges /mcp without a token, pointing at metadata served before the auth gate', async () => {
    const s = await start();
    await expectChallenge(await mcpPost(s.url), s.pub);
    const metadata = await fetch(`${s.base}/.well-known/oauth-protected-resource/mcp`);
    expect(metadata.status).toBe(200);
    expect(await metadata.json()).toMatchObject({ resource: `${s.pub}/mcp`, authorization_servers: [s.pub] });
  });

  it('connects an MCP client with an access token from the full flow', async () => {
    const s = await start();
    const { access } = await connect(s);
    const client = new Client({ name: 'test', version: '0.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(s.url), { requestInit: { headers: { authorization: `Bearer ${access}` } } }));
    closers.push(() => client.close());
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(4);
  });

  it('challenges an expired access token', async () => {
    const s = await start();
    const { access } = await connect(s);
    s.advance(3601_000);
    await expectChallenge(await mcpPost(s.url, { authorization: `Bearer ${access}` }), s.pub);
  });

  it('challenges a revoked access token', async () => {
    const s = await start();
    const { access, clientId } = await connect(s);
    s.store.revokeClient(clientId);
    await expectChallenge(await mcpPost(s.url, { authorization: `Bearer ${access}` }), s.pub);
  });

  it('challenges a token issued for another resource', async () => {
    const s = await start();
    const other = createOAuthServer({ store: s.store, publicUrl: new URL('https://other'), ownerToken: TOKEN, audit: () => {} });
    const { client } = s.store.registerClient({ name: 'Other', redirectUris: [REDIRECT], authMethod: 'none' }, 'https://other');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const approved = s.store.approve({ clientId: client.id, redirectUri: REDIRECT, codeChallenge: challenge, resource: 'https://other/mcp', state: null });
    if (!approved.ok) throw new Error('full');
    const token = (await other.fetch(new Request('https://other/token', form({
      grant_type: 'authorization_code', client_id: client.id, code: approved.code, redirect_uri: REDIRECT, code_verifier: verifier,
    })))) as Response;
    const { access_token: access } = (await token.json()) as { access_token: string };
    expect(s.store.verifyAccess(access)?.resource).toBe('https://other/mcp');
    await expectChallenge(await mcpPost(s.url, { authorization: `Bearer ${access}` }), s.pub);
  });

  it('still accepts KORDN_TOKEN on /mcp', async () => {
    const s = await start();
    expect((await mcpPost(s.url, { authorization: `Bearer ${TOKEN}` })).status).toBe(200);
  });

  it.each([
    ['/register', 9 * 1024, 'application/json'],
    ['/token', 17 * 1024, 'application/x-www-form-urlencoded'],
  ])('answers 413 to an oversized %s body', async (path, size, type) => {
    const s = await start();
    const res = await fetch(`${s.base}${path}`, { method: 'POST', headers: { 'content-type': type }, body: 'x'.repeat(size) });
    expect(res.status).toBe(413);
  });

  it('cuts off an oversized chunked /register upload soon after its 413', async () => {
    const s = await start();
    const started = Date.now();
    const { status, written } = await upload(`${s.base}/register`, 256 * 1024 * 1024);
    expect(process.platform === 'linux' ? [413] : [413, 0]).toContain(status);
    // Unauthenticated, so the refused bounds (64 KiB, 1 s, then hang up) apply, not the 64 MiB /
    // 5 s drain behind KORDN_TOKEN. Socket buffers absorb a few MiB on the client's side either
    // way, so the cut's timing is what tells the two apart.
    expect(written).toBeLessThan(32 * 1024 * 1024);
    expect(Date.now() - started).toBeLessThan(3_000);
  }, 15_000);

  it('refuses a foreign Origin on POST /authorize before the OAuth handler sees it', async () => {
    const s = await start();
    const res = await fetch(`${s.base}/authorize`, {
      ...form({ decision: 'approve' }),
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'https://evil.example' },
    });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'origin not allowed' });
  });

  it('answers a CORS preflight from a localhost browser client', async () => {
    const s = await start();
    const res = await fetch(`${s.base}/token`, {
      method: 'OPTIONS',
      headers: { origin: 'http://localhost:6274', 'access-control-request-method': 'POST' },
    });
    expect(res.status).toBe(204);
    expect(res.headers.get('access-control-allow-origin')).toBe('*');
  });

  it('accepts the public hostname as Host and answers with public URLs', async () => {
    const s = await start('https://kordn.example.net');
    const res = await raw(`${s.base}/.well-known/oauth-protected-resource/mcp`, { headers: { host: 'kordn.example.net' } });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toMatchObject({ resource: 'https://kordn.example.net/mcp' });
    const challenged = await raw(s.url, {
      method: 'POST',
      headers: { ...accept, host: 'kordn.example.net', origin: 'https://kordn.example.net', 'content-type': 'application/json' },
      body: listTools,
    });
    expect(challenged.status).toBe(401);
    expect(challenged.headers['www-authenticate']).toContain('resource_metadata="https://kordn.example.net/.well-known/oauth-protected-resource/mcp"');
  });
});

describe('HTTP without OAuth', () => {
  it('refuses the metadata path before auth, as before', async () => {
    const http = await serveHttp({ factory: () => createMcpServer({ agentId: policy.agentId, handleCall: async () => ({ ok: true, result: {} }) }), token: TOKEN, port: 0 });
    closers.push(() => http.close());
    const res = await fetch(http.url.replace('/mcp', '/.well-known/oauth-protected-resource'));
    expect(res.status).toBe(401);
    expect(res.headers.get('www-authenticate')).toBe('Bearer realm="kordn"');
  });
});
