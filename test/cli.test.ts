import { execFileSync, spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { Policy } from '../src/schema.js';

// Spawns the built CLI, so this is the path a real MCP client takes.

const root = resolve(import.meta.dirname, '..');
const cli = join(root, 'dist', 'index.js');
const policy = Policy.parse(policyJson);
const cleanup: (() => unknown)[] = [];

beforeAll(() => {
  execFileSync('npm', ['run', 'build', '--silent'], { cwd: root, stdio: 'pipe' });
}, 60_000);

afterEach(async () => {
  while (cleanup.length) await cleanup.pop()?.();
});

const tempDir = () => mkdtempSync(join(tmpdir(), 'kordn-cli-'));

async function stdioClient(args: string[] = [], versionNegotiation?: { mode: { pin: '2026-07-28' } }) {
  const client = new Client({ name: 'test', version: '0.0.0' }, versionNegotiation ? { versionNegotiation } : {});
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [cli, ...args], cwd: tempDir(), stderr: 'pipe' }));
  cleanup.push(() => client.close());
  return client;
}

/** Run the CLI to exit. Resolves with its code and output. */
function run(args: string[], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH ?? '', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => done({ code, stdout, stderr }));
  });
}

const balance = { name: 'af_get_balance', arguments: { resourceId: policy.resourceId } };

describe('kordn CLI', () => {
  it('builds an executable dist/index.js with a shebang, published as the kordn bin', () => {
    expect(readFileSync(cli, 'utf8').startsWith('#!/usr/bin/env node\n')).toBe(true);
    expect(statSync(cli).mode & 0o111).not.toBe(0);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { bin: unknown };
    expect(pkg.bin).toEqual({ kordn: 'dist/index.js' });
  });

  it.each([
    ['2025 (initialize)', undefined],
    ['2026-07-28 (stateless)', { mode: { pin: '2026-07-28' as const } }],
  ])('serves stdio with the example policy by default, from any cwd, over %s', async (_era, negotiation) => {
    const client = await stdioClient([], negotiation);
    expect((await client.listTools()).tools).toHaveLength(4);
    expect((await client.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
    expect((await client.callTool({ name: 'shell', arguments: {} })).structuredContent).toEqual({
      error: { code: 'UNKNOWN_ACTION' },
    });
  });

  it('loads --policy', async () => {
    const path = join(tempDir(), 'policy.json');
    writeFileSync(path, JSON.stringify({ ...policy, transfers: { ...policy.transfers, allow: false } }));
    const client = await stdioClient(['--policy', path]);
    const result = await client.callTool({
      name: 'af_propose_transfer',
      arguments: { resourceId: policy.resourceId, payeeId: 'utilities', amountMinor: 100, currency: 'USD', idempotencyKey: 'key-00000001' },
    });
    expect(result.structuredContent).toEqual({ error: { code: 'CAPABILITY_DISABLED' } });
  });

  it('refuses an invalid policy', async () => {
    const path = join(tempDir(), 'policy.json');
    writeFileSync(path, JSON.stringify({ ...policy, defaultDecision: 'allow' }));
    const { code, stderr } = await run(['--policy', path]);
    expect(code).not.toBe(0);
    expect(stderr).toMatch(/invalid policy/);
  });

  it.each([
    [['--nope']],
    [['--port', '3333']],
    [['--http', '--port', 'abc']],
    [['--http', '--port', '70000']],
    [['--guardian', '/tmp/x.sock', '--policy', 'p.json']],
    [['extra']],
  ])('rejects bad arguments %j', async (args) => {
    const { code, stderr } = await run(args, { KORDN_TOKEN: 'x'.repeat(32) });
    expect(code).toBe(2);
    expect(stderr).toMatch(/usage: kordn/);
  });

  it('refuses --http without KORDN_TOKEN', async () => {
    const { code, stderr } = await run(['--http', '--port', '0']);
    expect(code).not.toBe(0);
    expect(stderr).toMatch(/KORDN_TOKEN/);
  });

  it('serves --http with the token', async () => {
    const token = 'cli-token-0123456789abcdef';
    const child = spawn(process.execPath, [cli, '--http', '--port', '0'], {
      env: { PATH: process.env.PATH ?? '', KORDN_TOKEN: token },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    cleanup.push(() => child.kill());
    const url = await new Promise<string>((found, fail) => {
      let stderr = '';
      child.stderr.on('data', (d) => {
        stderr += d;
        const match = /http:\/\/127\.0\.0\.1:\d+\/mcp/.exec(stderr);
        if (match) found(match[0]);
      });
      child.on('close', () => fail(new Error(stderr)));
    });
    const denied = await fetch(url, { method: 'POST', body: '{}' });
    expect(denied.status).toBe(401);
    const client = new Client({ name: 'test', version: '0.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    cleanup.push(() => client.close());
    expect((await client.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
  });

  describe('--guardian', () => {
    it('forwards calls to the guardian socket', async () => {
      const path = join(tempDir(), 'g.sock');
      const guardian = createFakeGuardian({ policy });
      const server: Server = await serveGuardianSocket(guardian, policy.agentId, path);
      cleanup.push(() => server.close());
      const client = await stdioClient(['--guardian', path]);
      expect((await client.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
      expect((await client.callTool({ name: 'af_add_payee', arguments: { payeeId: 'x' } })).isError).toBe(true);
      // No arguments at all: the frame must still be valid so the guardian logs it.
      expect((await client.callTool({ name: 'shell' })).structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION' } });
      expect(await guardian.listActivity({ events: ['policy.denied'] })).toMatchObject([
        { agent: policy.agentId, reasonCode: 'UNKNOWN_ACTION' },
        { agent: policy.agentId, reasonCode: 'UNKNOWN_ACTION' },
      ]);
    });

    it('returns INTERNAL_UNAVAILABLE when the socket is down, never falling back', async () => {
      const client = await stdioClient(['--guardian', join(tempDir(), 'missing.sock')]);
      expect((await client.listTools()).tools).toHaveLength(4);
      const result = await client.callTool(balance);
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toEqual({ error: { code: 'INTERNAL_UNAVAILABLE' } });
    });
  });
});
