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

/** Raw request so tests can set Host, which fetch won't let us override. */
function raw(url: string, headers: Record<string, string>, body = '{}'): Promise<{ status: number; headers: Record<string, unknown> }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers } }, (res) => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers }));
    });
    req.on('error', reject);
    req.end(body);
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

  it('answers 413 to an oversized body', async () => {
    const { url } = await start();
    const res = await raw(url, { ...accept, authorization: `Bearer ${TOKEN}` }, 'x'.repeat(2 * 1024 * 1024));
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
