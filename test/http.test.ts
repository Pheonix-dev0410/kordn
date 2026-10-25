import { request } from 'node:http';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { afterEach, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { serveHttp } from '../src/http.js';
import { createMcpServer } from '../src/mcp-server.js';
import { Policy } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const TOKEN = 'test-token-0123456789abcdef0123456789';
const closers: (() => Promise<void>)[] = [];

afterEach(async () => {
  while (closers.length) await closers.pop()?.();
});

async function start(options: { allowedHosts?: string[] } = {}) {
  const guardian = createFakeGuardian({ policy });
  const handleCall = guardian.handleCall.bind(guardian);
  const http = await serveHttp({
    factory: () => createMcpServer({ agentId: policy.agentId, handleCall }),
    token: TOKEN,
    port: 0,
    ...options,
  });
  closers.push(() => http.close());
  return { ...http, guardian };
}

/**
 * Raw request so tests can set Host, which fetch won't let us override. A string body is
 * sent with Content-Length; an array is sent chunk by chunk with chunked encoding.
 */
function raw(
  url: string,
  headers: Record<string, string>,
  body: string | string[] = '{}',
): Promise<{ status: number; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
    });
    req.on('error', reject);
    if (typeof body === 'string') return req.end(body);
    const chunks = [...body];
    const next = (): void => {
      const chunk = chunks.shift();
      if (chunk === undefined || req.destroyed) return void req.end();
      if (req.write(chunk)) setImmediate(next);
      else req.once('drain', next);
    };
    next();
  });
}

/**
 * Stream up to `total` bytes as a chunked POST, as fast as the server takes them. Resolves
 * with the response status and how much was written before the server cut the connection.
 */
function upload(url: string, headers: Record<string, string>, total: number): Promise<{ status: number; written: number }> {
  return new Promise((resolve) => {
    let status = 0;
    let written = 0;
    const chunk = Buffer.alloc(64 * 1024, 'x');
    const req = request(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers } }, (res) => {
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

const listTools = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
const accept = { accept: 'application/json, text/event-stream' };

describe('HTTP transport', () => {
  it('refuses to start without a token, or with a short one', async () => {
    const factory = () => createMcpServer({ agentId: policy.agentId, handleCall: async () => ({ ok: true, result: {} }) });
    await expect(serveHttp({ factory, token: '', port: 0 })).rejects.toThrow(/KORDN_TOKEN/);
    await expect(serveHttp({ factory, token: 'x'.repeat(31), port: 0 })).rejects.toThrow(/KORDN_TOKEN .*32 characters/);
  });

  it('binds 127.0.0.1 and serves /mcp', async () => {
    const { url } = await start();
    expect(url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/mcp$/);
  });

  it.each([
    ['no token', {}],
    ['a wrong token', { authorization: `Bearer ${TOKEN.replace('0', '1')}` }],
    ['a token of another length', { authorization: `Bearer ${TOKEN}x` }],
    ['another scheme', { authorization: `Basic ${TOKEN}` }],
  ])('answers 401 with %s', async (_name, headers) => {
    const { url } = await start();
    const res = await raw(url, { ...accept, ...headers }, listTools);
    expect(res.status).toBe(401);
    expect(res.headers['www-authenticate']).toMatch(/^Bearer/);
  });

  it.each([
    ['401 without a token', {}, 401],
    ['403 for a foreign Host', { host: 'evil.example' }, 403],
  ])('cuts off an unauthenticated upload after its %s', async (_name, headers, code) => {
    const { url } = await start();
    const { status, written } = await upload(url, headers, 256 * 1024 * 1024);
    expect(status).toBe(code);
    // Kernel buffers absorb some data after the server stops reading; 256 MiB would mean it never did.
    expect(written).toBeLessThan(32 * 1024 * 1024);
  });

  it('answers 404 off /mcp, even with the token', async () => {
    const { url } = await start();
    const res = await raw(url.replace('/mcp', '/admin'), { ...accept, authorization: `Bearer ${TOKEN}` }, listTools);
    expect(res.status).toBe(404);
  });

  it.each([
    ['a foreign Host', { host: 'evil.example' }],
    ['a foreign Origin', { origin: 'http://evil.example' }],
    ['a null Origin', { origin: 'null' }],
  ])('answers 403 to %s (DNS rebinding), even with the token', async (_name, headers) => {
    const { url } = await start();
    const res = await raw(url, { ...accept, authorization: `Bearer ${TOKEN}`, ...headers }, listTools);
    expect(res.status).toBe(403);
  });

  it('accepts an extra allowed host, for a tunnel', async () => {
    const { url } = await start({ allowedHosts: ['kordn.example.net'] });
    const res = await raw(
      url,
      { ...accept, authorization: `Bearer ${TOKEN}`, host: 'kordn.example.net', origin: 'https://kordn.example.net' },
      listTools,
    );
    expect(res.status).toBe(200);
  });

  it.each([2, 8])('answers 413, not a connection reset, to a %i MiB body with Content-Length', async (mib) => {
    const { url } = await start();
    const body = 'x'.repeat(mib * 1024 * 1024);
    // A reset only shows up some of the time, so try a few.
    for (let i = 0; i < 8; i++) {
      const res = await fetch(url, { method: 'POST', headers: { ...accept, authorization: `Bearer ${TOKEN}` }, body });
      expect(res.status).toBe(413);
    }
  });

  it('answers 413 to an oversized chunked body', async () => {
    const { url } = await start();
    const chunks = Array.from({ length: 128 }, () => 'x'.repeat(64 * 1024));
    const res = await raw(url, { ...accept, authorization: `Bearer ${TOKEN}` }, chunks);
    expect(res.status).toBe(413);
  });

  it.each([
    ['2025 (initialize)', undefined],
    ['2026-07-28 (stateless)', { mode: { pin: '2026-07-28' as const } }],
  ])('works with the right token over %s', async (_era, versionNegotiation) => {
    const { url, guardian } = await start();
    const client = new Client({ name: 'test', version: '0.0.0' }, versionNegotiation ? { versionNegotiation } : {});
    await client.connect(
      new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${TOKEN}` } } }),
    );
    closers.push(() => client.close());
    const { tools } = await client.listTools();
    expect(tools).toHaveLength(4);
    const balance = await client.callTool({ name: 'af_get_balance', arguments: { resourceId: policy.resourceId } });
    expect(balance.structuredContent).toMatchObject({ currency: 'USD' });
    const shell = await client.callTool({ name: 'shell', arguments: {} });
    expect(shell.structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION' } });
    for (const params of [{ name: 'shell', arguments: 'str' }, { name: 42 }]) {
      const malformed = await client.request({ method: 'tools/call', params: params as never });
      expect(malformed.isError).toBe(true);
      expect(malformed.structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION' } });
    }
    expect(await guardian.listActivity({ events: ['policy.denied'] })).toHaveLength(3);
  });
});
