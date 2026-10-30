import { type ChildProcess, execFileSync, spawn } from 'node:child_process';
import { chmodSync, closeSync, existsSync, mkdirSync, mkdtempSync, openSync, readdirSync, readFileSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { Client, StreamableHTTPClientTransport } from '@modelcontextprotocol/client';
import { StdioClientTransport } from '@modelcontextprotocol/client/stdio';
import { afterEach, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from './fake-guardian.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { Policy } from '../src/schema.js';
import { login } from './admin-helpers.js';

// Spawns the built CLI, so this is the path a real MCP client takes.

const root = resolve(import.meta.dirname, '..');
const cli = join(root, 'dist', 'index.js');
const policy = Policy.parse(policyJson);
const cleanup: (() => unknown)[] = [];

afterEach(async () => {
  while (cleanup.length) await cleanup.pop()?.();
});

const tempDir = () => mkdtempSync(join(tmpdir(), 'kordn-cli-'));

async function stdioClient(args: string[] = [], versionNegotiation?: { mode: { pin: '2026-07-28' } }, state = tempDir()) {
  const client = new Client({ name: 'test', version: '0.0.0' }, versionNegotiation ? { versionNegotiation } : {});
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [cli, ...args], cwd: tempDir(), env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: state, XDG_CONFIG_HOME: tempDir() }, stderr: 'pipe' }));
  cleanup.push(() => client.close());
  return client;
}

// Long enough for a cold start, short enough that a CLI which wrongly keeps running
// (e.g. starts serving instead of refusing) fails fast instead of hanging the suite.
const DEADLINE_MS = 3000;

/** Run the CLI to exit, killing it at the deadline. Resolves with its code and output. */
function run(args: string[], env: Record<string, string> = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((done) => {
    const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    const timer = setTimeout(() => child.kill('SIGKILL'), DEADLINE_MS);
    cleanup.push(() => child.kill('SIGKILL'));
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ code, stdout, stderr });
    });
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

  it('packs the built CLI and the example policy, and nothing else of the repo', () => {
    const [packed] = JSON.parse(
      execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8' }),
    ) as [{ files: { path: string }[] }];
    const paths = packed.files.map((f) => f.path);
    expect(paths).toEqual(expect.arrayContaining(['dist/index.js', 'dist/mcp-server.js', 'examples/policy.json']));
    expect(paths.filter((p) => /^(src|test|docs)\//.test(p))).toEqual([]);
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')) as { scripts: Record<string, string> };
    expect(pkg.scripts.prepack).toBe('npm run build');
  });

  it.each([
    ['2025 (initialize)', undefined],
    ['2026-07-28 (stateless)', { mode: { pin: '2026-07-28' as const } }],
  ])('serves stdio with the example policy by default, from any cwd, over %s', async (_era, negotiation) => {
    const client = await stdioClient([], negotiation);
    expect((await client.listTools()).tools).toHaveLength(4);
    expect((await client.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
    expect((await client.callTool({ name: 'shell', arguments: {} })).structuredContent).toEqual({
      error: { code: 'UNKNOWN_ACTION', hint: expect.any(String) },
    });
    // Too far back says so, and how to fix it.
    const old = { name: 'af_list_transactions', arguments: { resourceId: 'mock-bank:checking-01', fromDate: '2000-01-01', limit: 5 } };
    expect((await client.callTool(old)).structuredContent).toEqual({ error: { code: 'LOOKBACK_LIMIT', hint: expect.stringContaining('Use a later date') } });
    for (const params of [{ name: 'shell', arguments: 'str' }, { name: 42 }]) {
      const malformed = await client.request({ method: 'tools/call', params: params as never });
      expect(malformed.structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION', hint: expect.any(String) } });
    }
  });

  it('loads --policy', async () => {
    const path = join(tempDir(), 'policy.json');
    writeFileSync(path, JSON.stringify({ ...policy, transfers: { ...policy.transfers, allow: false } }));
    const client = await stdioClient(['--policy', path]);
    const result = await client.callTool({
      name: 'af_propose_transfer',
      arguments: { resourceId: policy.resourceId, payeeId: 'utilities', amountMinor: 100, currency: 'USD', idempotencyKey: 'key-00000001' },
    });
    expect(result.structuredContent).toEqual({ error: { code: 'CAPABILITY_DISABLED', hint: expect.any(String) } });
  });

  it('keeps the ledger across restarts, so limits still hold after one', async () => {
    const state = tempDir();
    const transfer = (n: number) => ({
      name: 'af_propose_transfer',
      arguments: { resourceId: policy.resourceId, payeeId: 'utilities', amountMinor: 5000, currency: 'USD', idempotencyKey: `restart-key-${n}` },
    });
    const first = await stdioClient([], undefined, state);
    for (const n of [1, 2, 3]) expect((await first.callTool(transfer(n))).structuredContent).toMatchObject({ state: 'succeeded' });
    await first.close();
    const second = await stdioClient([], undefined, state);
    // A retry of an earlier key reports that transfer instead of sending another.
    expect((await second.callTool(transfer(1))).structuredContent).toMatchObject({ state: 'succeeded' });
    expect((await second.callTool(transfer(4))).structuredContent).toEqual({ error: { code: 'FREQUENCY_LIMIT', hint: expect.any(String) } });
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
    [['--http', '--allowed-host', 'kordn.example.net:443']],
    [['--http', '--allowed-host', 'https://kordn.example.net']],
    [['--http', '--allowed-host', 'kordn.example.net/mcp']],
    [['--http', '--allowed-host', '::1']],
    [['--http', '--allowed-host', '']],
    [['--http', '--allowed-host', '*.example.net']],
    [['--http', '--allowed-host', '*']],
    [['--http', '--allowed-host', 'kordn_host.example.net']],
    [['--admin', '--guardian', '/tmp/x.sock']],
    [['--admin-port', '0']],
    [['--admin', '--admin-port', 'abc']],
    [['contain', '--http']],
    [['contain', '--guardian', '/tmp/x.sock']],
    [['contain', '--port', '3333']],
    [['contain', 'extra']],
    [['contain', '--']],
    [['contain', '--admin-port', '0']],
    [['contain', '--image']],
  ])('rejects bad arguments %j', async (args) => {
    const { code, stderr } = await run(args, { KORDN_TOKEN: 'x'.repeat(32) });
    expect(code).toBe(2);
    expect(stderr).toMatch(/usage: kordn/);
  });

  it('refuses --http with a 31-character KORDN_TOKEN', async () => {
    const { code, stderr } = await run(['--http', '--port', '0'], { KORDN_TOKEN: 'x'.repeat(31) });
    expect(code).toBe(1);
    expect(stderr).toMatch(/KORDN_TOKEN must be set to a random secret of at least 32 characters/);
  });

  it('makes an --http token without KORDN_TOKEN and keeps it across restarts', async () => {
    const data = tempDir();
    chmodSync(data, 0o700);
    const file = join(data, 'http-token');
    const tokens: string[] = [];
    for (let i = 0; i < 2; i++) {
      const kordn = spawnCli(['--http', '--port', '0', '--data', data], {});
      const [, token, path] = await kordn.waitForStderr(/kordn: token ([0-9a-f]{64}) \(kept in (.+); KORDN_TOKEN overrides it\)\n/);
      expect(path).toBe(file);
      const [url] = /http:\/\/127\.0\.0\.1:\d+\/mcp/.exec(kordn.stderr())!;
      const client = new Client({ name: 'test', version: '0.0.0' });
      await client.connect(new StreamableHTTPClientTransport(new URL(url), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
      await client.close();
      tokens.push(token!);
      kordn.child.kill('SIGTERM');
      await kordn.exited;
    }
    expect(tokens[1]).toBe(tokens[0]);
    expect(statSync(file).mode & 0o777).toBe(0o600);
  });

  it('serves --http with the token', async () => {
    const token = 'cli-token-0123456789abcdef0123456789';
    const child = spawn(process.execPath, [cli, '--http', '--port', '0'], {
      env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), KORDN_TOKEN: token },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    cleanup.push(() => child.kill('SIGKILL'));
    const url = await new Promise<string>((found, fail) => {
      setTimeout(() => fail(new Error('no URL printed before the deadline')), DEADLINE_MS);
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
      expect((await client.callTool({ name: 'shell' })).structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION', hint: expect.any(String) } });
      for (const params of [{ name: 'shell', arguments: 'str' }, { name: 42 }]) {
        const malformed = await client.request({ method: 'tools/call', params: params as never });
        expect(malformed.structuredContent).toEqual({ error: { code: 'UNKNOWN_ACTION', hint: expect.any(String) } });
      }
      const denied = await guardian.listActivity({ events: ['policy.denied'] });
      expect(denied).toHaveLength(4);
      expect(denied.every((e) => e.agent === policy.agentId && e.reasonCode === 'UNKNOWN_ACTION')).toBe(true);
    });

    it('returns INTERNAL_UNAVAILABLE when the socket is down, never falling back', async () => {
      const client = await stdioClient(['--guardian', join(tempDir(), 'missing.sock')]);
      expect((await client.listTools()).tools).toHaveLength(4);
      const result = await client.callTool(balance);
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toEqual({ error: { code: 'INTERNAL_UNAVAILABLE', hint: expect.any(String) } });
    });
  });
});

// ---- --admin and kordn contain ----

interface Spawned {
  child: ChildProcess;
  stdout: () => string;
  stderr: () => string;
  /** Resolves with the first match of `pattern` on stderr; rejects at the deadline or on exit. */
  waitForStderr(pattern: RegExp, deadlineMs?: number): Promise<RegExpExecArray>;
  exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }>;
}

function spawnCli(args: string[], env: Record<string, string>, stdin: 'pipe' | 'ignore' = 'ignore'): Spawned {
  const child = spawn(process.execPath, [cli, ...args], { env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), ...env }, stdio: [stdin, 'pipe', 'pipe'] });
  cleanup.push(() => child.kill('SIGKILL'));
  let stdout = '';
  let stderr = '';
  child.stdout!.on('data', (d) => (stdout += d));
  child.stderr!.on('data', (d) => (stderr += d));
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((done) =>
    child.on('close', (code, signal) => done({ code, signal })),
  );
  return {
    child,
    stdout: () => stdout,
    stderr: () => stderr,
    exited,
    waitForStderr: (pattern, deadlineMs = DEADLINE_MS) =>
      new Promise((found, fail) => {
        const check = () => {
          const match = pattern.exec(stderr);
          if (match) {
            clearTimeout(timer);
            child.stderr!.off('data', check);
            found(match);
          }
        };
        const timer = setTimeout(() => fail(new Error(`no ${pattern} on stderr before the deadline:\n${stderr}`)), deadlineMs);
        child.stderr!.on('data', check);
        void exited.then(() => {
          check();
          fail(new Error(`exited without ${pattern} on stderr:\n${stderr}`));
        });
        check();
      }),
  };
}

/** A private XDG_RUNTIME_DIR, and the admin file a kordn with this pid writes there. */
function runtimeDir() {
  const dir = tempDir();
  chmodSync(dir, 0o700);
  return { dir, adminFile: (pid: number) => join(dir, 'kordn', `admin-${pid}.json`) };
}

interface AdminFile {
  url: string;
  token: string;
  pid: number;
  agentId: string;
}

function readAdminFile(path: string): AdminFile {
  return JSON.parse(readFileSync(path, 'utf8')) as AdminFile;
}

/** Logs in with the token from the admin file and returns the approvals page. */
async function adminPage(file: AdminFile): Promise<string> {
  const session = await login({ url: file.url, token: file.token, close: async () => {} });
  const page = await session.get('/approvals');
  expect(page.status).toBe(200);
  return page.body;
}

describe('--admin', () => {
  it('keeps stdout pure MCP, prints the URL and token to stderr, and leaves them in a private file until stdin closes', async () => {
    const runtime = runtimeDir();
    const kordn = spawnCli(['--admin'], { XDG_RUNTIME_DIR: runtime.dir }, 'pipe');
    const [, url] = await kordn.waitForStderr(/admin UI at (http:\/\/127\.0\.0\.1:\d+\/)/);
    const path = runtime.adminFile(kordn.child.pid!);
    expect(statSync(join(runtime.dir, 'kordn')).mode & 0o777).toBe(0o700);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const file = readAdminFile(path);
    expect(file).toEqual({ url, token: expect.any(String), pid: kordn.child.pid, agentId: policy.agentId });
    expect(kordn.stderr()).toContain(file.token);
    expect(kordn.stderr()).toContain(path);
    expect(await adminPage(file)).toContain('Guard mode.');

    // An MCP exchange on stdout, with nothing else in between.
    kordn.child.stdin!.write(
      `${JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '0' } } })}\n`,
    );
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => kordn.stdout().includes('\n') && (clearInterval(poll), resolve()), 10);
    });
    kordn.child.stdin!.end();
    expect(await kordn.exited).toEqual({ code: 0, signal: null });
    const lines = kordn.stdout().split('\n').filter(Boolean);
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) expect(JSON.parse(line)).toMatchObject({ jsonrpc: '2.0' });
    expect(existsSync(path)).toBe(false);
  });

  it('serves a working MCP client alongside the admin UI', async () => {
    const runtime = runtimeDir();
    const client = new Client({ name: 'test', version: '0.0.0' });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [cli, '--admin'],
      cwd: tempDir(),
      env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), XDG_RUNTIME_DIR: runtime.dir },
      stderr: 'pipe',
    });
    await client.connect(transport);
    cleanup.push(() => client.close());
    expect((await client.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
    expect(existsSync(runtime.adminFile(transport.pid!))).toBe(true);
  });

  it.each(['SIGINT', 'SIGTERM', 'SIGHUP'] as const)('removes the admin file on %s', async (signal) => {
    const runtime = runtimeDir();
    const kordn = spawnCli(['--admin', '--admin-port', '0'], { XDG_RUNTIME_DIR: runtime.dir }, 'pipe');
    await kordn.waitForStderr(/admin UI at/);
    const path = runtime.adminFile(kordn.child.pid!);
    expect(existsSync(path)).toBe(true);
    kordn.child.kill(signal);
    await kordn.exited;
    expect(existsSync(path)).toBe(false);
  });

  it('runs with --http, sharing the guardian', async () => {
    const runtime = runtimeDir();
    const token = 'cli-token-0123456789abcdef0123456789';
    const kordn = spawnCli(['--http', '--port', '0', '--admin'], { XDG_RUNTIME_DIR: runtime.dir, KORDN_TOKEN: token });
    await kordn.waitForStderr(/admin UI at/);
    const [mcpUrl] = await kordn.waitForStderr(/http:\/\/127\.0\.0\.1:\d+\/mcp/);
    const client = new Client({ name: 'test', version: '0.0.0' });
    await client.connect(new StreamableHTTPClientTransport(new URL(mcpUrl), { requestInit: { headers: { authorization: `Bearer ${token}` } } }));
    cleanup.push(() => client.close());
    await client.callTool({ name: 'shell', arguments: {} });
    const file = readAdminFile(runtime.adminFile(kordn.child.pid!));
    const session = await login({ url: file.url, token: file.token, close: async () => {} });
    expect((await session.get('/activity')).body).toContain('UNKNOWN_ACTION');
    kordn.child.kill('SIGTERM');
    await kordn.exited;
    expect(existsSync(runtime.adminFile(kordn.child.pid!))).toBe(false);
  });

  it('names the admin file when XDG_RUNTIME_DIR does not exist, and fails closed', async () => {
    const missing = join(tempDir(), 'no-such-runtime-dir');
    const { code, stderr } = await run(['--admin'], { XDG_RUNTIME_DIR: missing });
    expect(code).toBe(1);
    expect(stderr).toMatch(new RegExp(`could not write the admin file ${missing}/kordn/admin-\\d+\\.json \\(directory ${missing}/kordn\\): ENOENT`));
  });

  it('fails without serving if the admin file cannot be written safely', async () => {
    const runtime = runtimeDir();
    mkdirSync(join(runtime.dir, 'kordn'), { mode: 0o755 });
    chmodSync(join(runtime.dir, 'kordn'), 0o755);
    const { code, stderr } = await run(['--admin'], { XDG_RUNTIME_DIR: runtime.dir });
    expect(code).toBe(1);
    expect(stderr).toMatch(/refusing to use .* for the admin file/);
  });
});

// kordn contain refuses to run anywhere but Linux.
describe.runIf(process.platform === 'linux')('kordn contain (fake docker)', () => {
  const CONTAINER_ID = 'c'.repeat(64);
  const CONTAIN_DEADLINE_MS = 15_000;

  /** A PATH whose `docker` is the fake, a private TMPDIR, a runtime dir, and the docker call log. */
  function fakeDockerEnv(extra: Record<string, string> = {}) {
    const bin = tempDir();
    symlinkSync(join(root, 'test/fixtures/fake-docker.mjs'), join(bin, 'docker'));
    const tmp = tempDir();
    const runtime = runtimeDir();
    const log = join(tempDir(), 'docker.log');
    const env = {
      PATH: `${bin}:${process.env.PATH ?? ''}`,
      XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(),
      TMPDIR: tmp,
      XDG_RUNTIME_DIR: runtime.dir,
      FAKE_DOCKER_LOG: log,
      FAKE_DOCKER_MODE: 'flow',
      ...extra,
    };
    const calls = () => (existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as string[]) : []);
    /** The probe script kordn piped into the container. */
    const probe = () => readFileSync(`${log}.probe`, 'utf8');
    return { env, tmp, runtime, calls, probe };
  }

  it('reaps, prints the report, runs the agent and exits with its code', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_AGENT_EXIT: '7' });
    const kordn = spawnCli(['contain'], fake.env);
    expect((await kordn.exited).code).toBe(7);
    expect(kordn.stderr()).toMatch(/kordn contain: GUARD mode \(linux, image \S+\)/);
    expect(kordn.stderr()).toMatch(/isolation checks? failed/);
    expect(kordn.stdout()).toBe('agent | agent ran\n');
    const calls = fake.calls();
    expect(calls.findIndex((c) => c[0] === 'ps' && c.includes('label=kordn.contain'))).toBeLessThan(calls.findIndex((c) => c[0] === 'run'));
    expect(calls.find((c) => c[0] === 'image')).toContain('kordn-sandbox');
    expect(calls.at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
    expect(readdirSync(fake.tmp)).toEqual([]);
  });

  it("can't forge an unprefixed line by interleaving stdout and stderr when both go to one file", async () => {
    const chunks = [
      ['out', 'a'],
      ['err', 'b\n'],
      ['out', 'kordn contain: CONTAIN mode (linux, image sha256:forged)\n'],
    ].map(([stream, data]) => [stream, Buffer.from(data!).toString('base64')]);
    const fake = fakeDockerEnv({ FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(chunks) });
    // kordn contain >file 2>&1
    const file = join(tempDir(), 'out.txt');
    const fd = openSync(file, 'w');
    const child = spawn(process.execPath, [cli, 'contain'], { env: { PATH: process.env.PATH ?? '', XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), ...fake.env }, stdio: ['ignore', fd, fd] });
    closeSync(fd);
    cleanup.push(() => child.kill('SIGKILL'));
    expect(await new Promise((done) => child.on('close', done))).toBe(0);
    const lines = readFileSync(file, 'utf8').split('\n').filter(Boolean);
    expect(lines.filter((l) => l.startsWith('kordn contain:'))).toEqual([expect.stringMatching(/^kordn contain: GUARD mode/)]);
    expect(lines.filter((l) => /^agent!? \| /.test(l))).toEqual([
      'agent | a',
      'agent! | b',
      'agent | kordn contain: CONTAIN mode (linux, image sha256:forged)',
    ]);
    // Everything else is kordn's own: the report's check lines and the failure summary.
    expect(lines.filter((l) => !/^agent!? \| /.test(l)).every((l) => /^(kordn|  (ok  |FAIL)  |\d+ isolation check)/.test(l))).toBe(true);
  }, CONTAIN_DEADLINE_MS);

  it("prefixes the agent's lines and makes its escape sequences inert, so it can't forge kordn's report", async () => {
    const chunks = [
      ['out', '\x1b[1A\x1b[2Kkordn contain: CONTAIN mode (linux, image sha256:x)\n'],
      ['err', '\x1b]52;c;aGVsbG8=\x07\x1b]0;kordn\x07kordn: admin UI: contain mode\r\n'],
    ].map(([stream, data]) => [stream, Buffer.from(data!).toString('base64')]);
    const fake = fakeDockerEnv({ FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(chunks) });
    const kordn = spawnCli(['contain'], fake.env);
    expect((await kordn.exited).code).toBe(0);
    expect(kordn.stdout()).toBe('agent | [1A[2Kkordn contain: CONTAIN mode (linux, image sha256:x)\n');
    expect(kordn.stderr()).toContain('agent! | ]52;c;aGVsbG8=]0;kordnkordn: admin UI: contain mode\n');
    expect(kordn.stderr()).not.toContain('\x1b');
    // The only unprefixed report line is kordn's own.
    expect(kordn.stderr().match(/^kordn contain: \w+ mode/gm)).toEqual(['kordn contain: GUARD mode']);
  });

  it('a --require-contain refusal racing a signal exits with the signal code, not 1', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_RM_SLOW: '1' });
    const kordn = spawnCli(['contain', '--require-contain'], fake.env);
    // The refusal is decided; the signal arrives while the container is being removed.
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => fake.calls().some((c) => c[0] === 'rm') && (clearInterval(poll), resolve()), 20);
    });
    kordn.child.kill('SIGTERM');
    expect(await kordn.exited).toEqual({ code: 143, signal: null });
    expect(kordn.stderr()).toMatch(/GUARD mode/);
  }, CONTAIN_DEADLINE_MS);

  it('passes --image and the command after -- to the sandbox', async () => {
    const fake = fakeDockerEnv();
    const kordn = spawnCli(['contain', '--image', 'kordn-test-image', '--', '/nodejs/bin/node', '/app/sandbox/other.mjs'], fake.env);
    expect((await kordn.exited).code).toBe(0);
    expect(fake.calls().find((c) => c[0] === 'image')).toContain('kordn-test-image');
    expect(fake.calls().filter((c) => c[0] === 'exec').at(-1)).toEqual(['exec', '-i', CONTAINER_ID, '/nodejs/bin/node', '/app/sandbox/other.mjs']);
  });

  it('--require-contain refuses to run the agent on a Guard report, and shuts the admin UI down as refused', async () => {
    const fake = fakeDockerEnv();
    const kordn = spawnCli(['contain', '--require-contain', '--admin'], fake.env);
    const [, url] = await kordn.waitForStderr(/admin UI at (\S+)/, CONTAIN_DEADLINE_MS);
    expect((await kordn.exited).code).toBe(1);
    expect(kordn.stderr()).toMatch(/GUARD mode/);
    expect(kordn.stderr()).toMatch(/admin UI: refused, shutting it down/);
    expect(kordn.stderr()).toMatch(/--require-contain/);
    expect(fake.calls().filter((c) => c[0] === 'exec' && !c.includes('--input-type=module'))).toEqual([]);
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
    expect(existsSync(fake.runtime.adminFile(kordn.child.pid!))).toBe(false);
    await expect(fetch(url!)).rejects.toThrow();
  });

  it('starts the admin UI before the checks, probes its real port, shows the result, and cleans everything up on SIGTERM', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_MODE: 'hang', FAKE_DOCKER_PROBE_DELAY_MS: '1500' });
    const kordn = spawnCli(['contain', '--admin'], fake.env);
    await kordn.waitForStderr(/admin UI at/, CONTAIN_DEADLINE_MS);
    const path = fake.runtime.adminFile(kordn.child.pid!);
    const file = readAdminFile(path);
    const port = new URL(file.url).port;

    // The probe is still running: the UI claims nothing about containment yet.
    expect(kordn.stderr()).not.toMatch(/kordn contain: \w+ mode/);
    const checking = await adminPage(file);
    expect(checking).toContain('Checking isolation');
    expect(checking).not.toMatch(/contain mode/i);

    await kordn.waitForStderr(/admin UI: guard mode/, CONTAIN_DEADLINE_MS);
    expect(await adminPage(file)).toContain('Guard mode.');
    // The checks probed the real admin port, on both loopback addresses.
    expect(fake.probe()).toContain(`{"host":"127.0.0.1","port":${port}}`);
    expect(fake.probe()).toContain(`{"host":"::1","port":${port}}`);
    // The admin UI first, then the report, then the mode switch.
    const err = kordn.stderr();
    expect(err.indexOf('admin UI at')).toBeLessThan(err.indexOf('kordn contain: GUARD mode'));
    expect(err.indexOf('kordn contain: GUARD mode')).toBeLessThan(err.indexOf('admin UI: guard mode'));
    // The agent's output is streamed: it shows up while the agent is still running.
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => kordn.stdout() === 'agent | agent started\n' && (clearInterval(poll), resolve()), 20);
    });

    kordn.child.kill('SIGTERM');
    expect(await kordn.exited).toEqual({ code: 143, signal: null });
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
    expect(existsSync(path)).toBe(false);
    expect(readdirSync(fake.tmp)).toEqual([]);
    await expect(fetch(file.url)).rejects.toThrow();
  }, CONTAIN_DEADLINE_MS);

  it('stops at once on a signal during the reaper, before the admin UI or the sandbox start', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_PS_SLOW: '1' });
    const kordn = spawnCli(['contain', '--admin'], fake.env);
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => fake.calls().some((c) => c[0] === 'ps') && (clearInterval(poll), resolve()), 20);
    });
    const started = Date.now();
    kordn.child.kill('SIGTERM');
    expect(await kordn.exited).toEqual({ code: 143, signal: null });
    expect(Date.now() - started).toBeLessThan(3000);
    expect(kordn.stderr()).not.toMatch(/admin UI|login token/);
    expect(fake.calls().map((c) => c[0])).not.toContain('run');
  }, CONTAIN_DEADLINE_MS);

  it('cleans up the container and the admin UI on SIGTERM during the checks', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_PROBE_DELAY_MS: '5000' });
    const kordn = spawnCli(['contain', '--admin'], fake.env);
    await kordn.waitForStderr(/admin UI at/, CONTAIN_DEADLINE_MS);
    const path = fake.runtime.adminFile(kordn.child.pid!);
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => fake.calls().some((c) => c.includes('--input-type=module')) && (clearInterval(poll), resolve()), 20);
    });
    kordn.child.kill('SIGTERM');
    expect(await kordn.exited).toEqual({ code: 143, signal: null });
    expect(kordn.stderr()).not.toMatch(/kordn contain: \w+ mode/);
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
    expect(existsSync(path)).toBe(false);
    expect(readdirSync(fake.tmp)).toEqual([]);
  }, CONTAIN_DEADLINE_MS);

  it('treats SIGHUP (terminal closed, parent gone) like SIGTERM: full cleanup, exit 129', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_MODE: 'hang' });
    const kordn = spawnCli(['contain', '--admin'], fake.env);
    await kordn.waitForStderr(/admin UI: guard mode/, CONTAIN_DEADLINE_MS);
    const path = fake.runtime.adminFile(kordn.child.pid!);
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => kordn.stdout() === 'agent | agent started\n' && (clearInterval(poll), resolve()), 20);
    });
    kordn.child.kill('SIGHUP');
    expect(await kordn.exited).toEqual({ code: 129, signal: null });
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
    expect(existsSync(path)).toBe(false);
    expect(readdirSync(fake.tmp)).toEqual([]);
  }, CONTAIN_DEADLINE_MS);

  it('a second signal exits without waiting for cleanup', async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_MODE: 'hang', FAKE_DOCKER_RM_SLOW: '1' });
    const kordn = spawnCli(['contain', '--admin'], fake.env);
    await kordn.waitForStderr(/admin UI: guard mode/, CONTAIN_DEADLINE_MS);
    const path = fake.runtime.adminFile(kordn.child.pid!);
    kordn.child.kill('SIGINT');
    await new Promise<void>((resolve) => {
      const poll = setInterval(() => fake.calls().some((c) => c[0] === 'rm') && (clearInterval(poll), resolve()), 20);
    });
    const started = Date.now();
    kordn.child.kill('SIGINT');
    expect((await kordn.exited).code).toBe(130);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(kordn.stderr()).toMatch(/before cleanup finished/);
    expect(existsSync(path)).toBe(false);
  }, CONTAIN_DEADLINE_MS);

  it("says the agent's docker exec was killed by a signal, not that it timed out", async () => {
    const fake = fakeDockerEnv({ FAKE_DOCKER_AGENT_SIGNAL: 'SIGKILL' });
    const kordn = spawnCli(['contain'], fake.env);
    expect((await kordn.exited).code).toBe(1);
    expect(kordn.stderr()).toMatch(/kordn: the agent's docker exec was killed by SIGKILL/);
    expect(kordn.stderr()).not.toMatch(/timed out/);
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
  });

  it("says once that stdout closed when kordn's reader goes away (| head -1), and cleans up", async () => {
    const lines = Array.from({ length: 20 }, (_, i) => ['out', Buffer.from(`line ${i}\n`).toString('base64')]);
    const fake = fakeDockerEnv({ FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(lines) });
    const kordn = spawnCli(['contain'], fake.env);
    kordn.child.stdout!.once('data', () => kordn.child.stdout!.destroy());
    expect((await kordn.exited).code).toBe(0);
    expect(kordn.stderr().match(/kordn: stdout closed; dropping the agent's stdout/g)).toHaveLength(1);
    expect(fake.calls().at(-1)).toEqual(['rm', '--force', CONTAINER_ID]);
  }, CONTAIN_DEADLINE_MS);

  it('fails cleanly when docker is missing', async () => {
    const { code, stderr } = await run(['contain'], { PATH: tempDir() });
    expect(code).toBe(1);
    expect(stderr).toMatch(/^kordn: .*docker/i);
    expect(stderr).not.toMatch(/\n\s+at /);
  });
});

describe('kordn setup', () => {
  /** Runs setup with these answers on stdin, one per line. */
  function setup(answers: string[], config: string, state: string) {
    return new Promise<{ code: number | null; stdout: string; stderr: string }>((done) => {
      const child = spawn(process.execPath, [cli, 'setup'], { env: { PATH: process.env.PATH ?? '', XDG_CONFIG_HOME: config, XDG_STATE_HOME: state }, stdio: ['pipe', 'pipe', 'pipe'] });
      cleanup.push(() => child.kill('SIGKILL'));
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (d) => (stdout += d));
      child.stderr.on('data', (d) => (stderr += d));
      child.on('close', (code) => done({ code, stdout, stderr }));
      child.stdin.end(`${answers.join('\n')}\n`);
    });
  }

  async function client(config: string, state: string, args: string[] = [], env: Record<string, string> = {}) {
    const c = new Client({ name: 'test', version: '0.0.0' });
    await c.connect(new StdioClientTransport({ command: process.execPath, args: [cli, ...args], cwd: tempDir(), env: { PATH: process.env.PATH ?? '', XDG_CONFIG_HOME: config, XDG_STATE_HOME: state, ...env }, stderr: 'pipe' }));
    cleanup.push(() => c.close());
    return c;
  }

  const transfer = (resourceId: string, payeeId: string, amountMinor: number, key: string) =>
    ({ name: 'af_propose_transfer', arguments: { resourceId, payeeId, amountMinor, currency: 'USD', idempotencyKey: key } });

  it('saves the mock bank with your limits, and a plain kordn enforces them', async () => {
    const [config, state] = [tempDir(), tempDir()];
    // Own limits instead of the suggested ones; a bad amount and a payment over the daily total are asked again.
    const { code, stdout } = await setup(['', 'n', '200', 'ten', '500', '50', '2', '30'], config, state);
    expect(code).toBe(0);
    expect(stdout).toContain('Enter an amount like 100');
    expect(stdout).toContain("That's more than your daily total of $200. Enter $200 or less.");
    expect(stdout).toContain('Your limits:\n  - at most $200 a day in total\n  - at most $50 for any one payment\n  - at most 2 payments a day\n  - payments over $30 wait');
    const dir = join(config, 'kordn');
    expect(statSync(dir).mode & 0o777).toBe(0o700);
    expect(statSync(join(dir, 'policy.json')).mode & 0o777).toBe(0o600);
    expect(existsSync(join(dir, 'bank.json'))).toBe(false);

    const c = await client(config, state);
    const id = 'mock-bank:checking-01';
    expect((await c.callTool(transfer(id, 'utilities', 5_001, 'setup-key-01'))).structuredContent).toEqual({ error: { code: 'SINGLE_LIMIT', hint: expect.any(String) } });
    expect((await c.callTool(transfer(id, 'utilities', 3_001, 'setup-key-02'))).structuredContent).toMatchObject({ state: 'pending_approval' });
    expect((await c.callTool(transfer(id, 'landlord', 1_000, 'setup-key-03'))).structuredContent).toMatchObject({ state: 'succeeded' });
  });

  it('saves PayPal payees and keys privately, and kordn uses them without the environment', async () => {
    const [config, state] = [tempDir(), tempDir()];
    const answers = ['2', '', 'client-id-1', 'secret-1', 'Bad Name', 'landlord', 'not-an-email', 'me@personal.example.com', '', '', 'n'];
    const { code, stdout } = await setup(answers, config, state);
    expect(code).toBe(0);
    expect(stdout).toContain('Suggested:\n  - at most $250 a day in total\n  - at most $100 for any one payment\n  - at most 3 payments a day\n  - payments over $75 wait');
    expect(stdout).toContain('Use lowercase letters');
    expect(stdout).toContain("doesn't look like their PayPal email");
    expect(stdout).not.toContain('secret-1');
    const dir = join(config, 'kordn');
    expect(JSON.parse(readFileSync(join(dir, 'bank.json'), 'utf8'))).toEqual({ provider: 'paypal', payees: { landlord: 'me@personal.example.com' } });
    expect(readFileSync(join(dir, 'keys.env'), 'utf8')).toBe('PAYPAL_CLIENT_ID=client-id-1\nPAYPAL_CLIENT_SECRET=secret-1\n');
    for (const name of ['policy.json', 'bank.json', 'keys.env']) expect(statSync(join(dir, name)).mode & 0o777).toBe(0o600);

    // Without the saved keys openBank would refuse to start; listing tools needs no network.
    const { tools } = await (await client(config, state)).listTools();
    expect(tools[0]!.description).toContain('resourceId is "paypal:main"');

    // Back to the mock bank: the PayPal files go.
    expect((await setup(['1', ''], config, state)).code).toBe(0);
    expect(existsSync(join(dir, 'bank.json')) || existsSync(join(dir, 'keys.env'))).toBe(false);
  });

  it('sets up real money only when typed out, with small limits and approval for every payment', async () => {
    const [config, state] = [tempDir(), tempDir()];
    const refused = await setup(['2', '2', 'yes'], config, state);
    expect(refused.code).not.toBe(0);
    expect(refused.stderr).toContain('not confirmed; nothing saved');
    expect(existsSync(join(config, 'kordn'))).toBe(false);

    // A Stripe test key is refused for live; the live key is taken.
    const { code, stdout } = await setup(['3', '2', 'Real Money', 'sk_test_x', 'rk_live_x', 'landlord', 'acct_landlord01', '', '', 'n'], config, state);
    expect(code).toBe(0);
    expect(stdout).toContain('Live moves real money');
    expect(stdout).toContain('Use a live key: it starts with rk_live_ or sk_live_.');
    expect(stdout).toContain('Suggested:\n  - at most $20 a day in total\n  - at most $10 for any one payment\n  - at most 3 payments a day\n  - every payment waits until you approve it on the dashboard');
    expect(stdout).toContain('kordn now guards your real Stripe account (live: real money).');
    const dir = join(config, 'kordn');
    expect(JSON.parse(readFileSync(join(dir, 'bank.json'), 'utf8'))).toEqual({ provider: 'stripe', payees: { landlord: 'acct_landlord01' }, live: true });
    expect(JSON.parse(readFileSync(join(dir, 'policy.json'), 'utf8')).transfers).toMatchObject({ maxSingleMinor: 1_000, maxCumulativeMinor: 2_000, humanApprovalAboveMinor: 0 });

    // A plain kordn takes the live key without --live, and says it's live.
    const started = await run([], { XDG_CONFIG_HOME: config, XDG_STATE_HOME: state });
    expect(started.stderr).toContain('kordn: LIVE: guarding your real Stripe account; payments move real money');
    expect(started.stderr).not.toContain('--live');

    // And a test key in test mode.
    expect((await setup(['3', '', 'rk_live_x', 'sk_test_x', 'landlord', 'acct_landlord01', '', '', 'n'], config, state)).stdout).toContain('Use a test key');
  });

  it('is ignored when --policy is given', async () => {
    const [config, state] = [tempDir(), tempDir()];
    expect((await setup(['2', '', 'c', 's', 'landlord', 'me@personal.example.com', '', '', 'n'], config, state)).code).toBe(0);
    const c = await client(config, state, ['--policy', join(root, 'examples', 'policy.json')]);
    expect((await c.callTool(balance)).structuredContent).toMatchObject({ currency: 'USD' });
  });
});

describe('--tunnel', () => {
  /** A stand-in cloudflared on PATH: prints a quick-tunnel URL and stays up, recording its pid. */
  function fakeCloudflared(): { path: string; pidFile: string } {
    const dir = tempDir();
    const pidFile = join(dir, 'pid');
    writeFileSync(join(dir, 'cloudflared'), `#!/bin/sh
echo $$ > '${pidFile}'
echo 'INF Requesting new quick Tunnel on https://api.trycloudflare.com...' >&2
echo 'INF |  https://four-words-in-here.trycloudflare.com  |' >&2
exec sleep 30
`, { mode: 0o755 });
    return { path: `${dir}:${process.env.PATH ?? ''}`, pidFile };
  }

  it.each([
    [['--tunnel'], /needs --http/],
    [['--http', '--tunnel', '--public-url', 'https://x.example'], /conflict/],
    [['--http', '--tunnel', '--guardian', '/tmp/s'], /conflict/],
    [['--http', '--tunnel', '--port', '0'], /fixed --port/],
  ])('rejects %j', async (args, message) => {
    const { code, stderr } = await run(args, { KORDN_TOKEN: 'x'.repeat(32) });
    expect(code).toBe(2);
    expect(stderr).toMatch(message);
  });

  it('says how to get cloudflared when it is missing', async () => {
    const { code, stderr } = await run(['--http', '--tunnel', '--port', '45871', '--data', tempDir()], { PATH: tempDir() });
    expect(code).toBe(1);
    expect(stderr).toMatch(/--tunnel needs cloudflared: brew install cloudflared/);
  });

  it("serves OAuth on the tunnel's URL and stops cloudflared on exit", async () => {
    const { path, pidFile } = fakeCloudflared();
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as { port: number };
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const data = tempDir();
    chmodSync(data, 0o700);
    const kordn = spawnCli(['--http', '--tunnel', '--port', String(port), '--data', data], { PATH: path });
    await kordn.waitForStderr(/kordn: OAuth on for https:\/\/four-words-in-here\.trycloudflare\.com\/mcp\n/);
    await kordn.waitForStderr(/kordn: token [0-9a-f]{64}/);
    const pid = Number(readFileSync(pidFile, 'utf8'));
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
    expect(kordn.stderr()).not.toContain('tunnel stopped');
    await expect.poll(() => { try { process.kill(pid, 0); return true; } catch { return false; } }).toBe(false);
  });
});

describe('--ngrok', () => {
  /**
   * A stand-in ngrok on PATH: logs JSON like ngrok, records its arguments and how often it
   * started. FAKE_NGROK=auth fails like a missing authtoken; drop exits soon after the first start.
   */
  function fakeNgrok(): { path: string; dir: string } {
    const dir = tempDir();
    writeFileSync(join(dir, 'ngrok'), `#!/bin/sh
echo "$@" > '${dir}/args'
n=$(cat '${dir}/count' 2>/dev/null || echo 0); n=$((n+1)); echo $n > '${dir}/count'
echo $$ > '${dir}/pid'
if [ "$FAKE_NGROK" = auth ]; then
  printf '%s\\n' '{"err":"authentication failed: This ngrok session is not authenticated.\\r\\n\\r\\nERR_NGROK_4018\\r\\n","lvl":"crit","msg":"command failed"}'
  exit 1
fi
url=""; prev=""; for a in "$@"; do [ "$prev" = "--url" ] && url="$a"; prev="$a"; done
echo '{"addr":"127.0.0.1:4040","lvl":"info","msg":"starting web service"}'
echo "{\\"lvl\\":\\"info\\",\\"msg\\":\\"started tunnel\\",\\"url\\":\\"$url\\"}"
if [ "$FAKE_NGROK" = drop ] && [ "$n" = 1 ]; then sleep 1; exit 1; fi
exec sleep 30
`, { mode: 0o755 });
    return { path: `${dir}:${process.env.PATH ?? ''}`, dir };
  }

  async function freePort(): Promise<number> {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as { port: number };
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    return port;
  }

  function privateDir(): string {
    const data = tempDir();
    chmodSync(data, 0o700);
    return data;
  }

  it.each([
    [['--ngrok', 'name.ngrok-free.app'], /needs --http/],
    [['--http', '--ngrok', 'name.ngrok-free.app', '--tunnel'], /conflict/],
    [['--http', '--ngrok', 'name.ngrok-free.app', '--public-url', 'https://x.example'], /conflict/],
    [['--http', '--ngrok', 'name.ngrok-free.app', '--port', '0'], /fixed --port/],
    [['--http', '--ngrok', 'http://name.ngrok-free.app'], /takes the domain you claimed/],
    [['--http', '--ngrok', 'name.ngrok-free.app/path'], /takes the domain you claimed/],
    [['--http', '--ngrok', 'https://four-words-in-here.trycloudflare.com/mcp.ngrok-free.app'], /dashboard\.ngrok\.com under Domains/],
    [['--http', '--ngrok', 'four-words-in-here.trycloudflare.com'], /without \/mcp/],
  ])('rejects %j', async (args, message) => {
    const { code, stderr } = await run(args, { KORDN_TOKEN: 'x'.repeat(32) });
    expect(code).toBe(2);
    expect(stderr).toMatch(message);
  });

  it('says how to get ngrok, and how to add the authtoken', async () => {
    const missing = await run(['--http', '--ngrok', 'name.ngrok-free.app', '--port', '45872', '--data', privateDir()], { PATH: tempDir() });
    expect(missing.code).toBe(1);
    expect(missing.stderr).toMatch(/--ngrok needs ngrok: brew install ngrok/);
    const { path } = fakeNgrok();
    const unauthenticated = await run(['--http', '--ngrok', 'name.ngrok-free.app', '--port', '45873', '--data', privateDir()], { PATH: path, FAKE_NGROK: 'auth' });
    expect(unauthenticated.code).toBe(1);
    expect(unauthenticated.stderr).toContain('ngrok needs your authtoken: sign up at dashboard.ngrok.com, then run ngrok config add-authtoken <token>');
  });

  it('serves OAuth on your domain, with the inspector off, and stops ngrok on exit', async () => {
    const { path, dir } = fakeNgrok();
    const port = await freePort();
    const kordn = spawnCli(['--http', '--ngrok', 'https://name.ngrok-free.app/', '--port', String(port), '--data', privateDir()], { PATH: path });
    await kordn.waitForStderr(/kordn: OAuth on for https:\/\/name\.ngrok-free\.app\/mcp\n/);
    expect(readFileSync(join(dir, 'args'), 'utf8').trim()).toBe(
      `http 127.0.0.1:${port} --url https://name.ngrok-free.app --inspect=false --log stdout --log-format json`,
    );
    const pid = Number(readFileSync(join(dir, 'pid'), 'utf8'));
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
    await expect.poll(() => { try { process.kill(pid, 0); return true; } catch { return false; } }).toBe(false);
  });

  it('starts ngrok again on the same domain when it stops', async () => {
    const { path, dir } = fakeNgrok();
    const kordn = spawnCli(['--http', '--ngrok', 'name.ngrok-free.app', '--port', String(await freePort()), '--data', privateDir()], { PATH: path, FAKE_NGROK: 'drop' });
    await kordn.waitForStderr(/kordn: ngrok stopped; starting it again on https:\/\/name\.ngrok-free\.app\n/);
    await kordn.waitForStderr(/kordn: ngrok is back\n/);
    expect(readFileSync(join(dir, 'count'), 'utf8').trim()).toBe('2');
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
  });
});

describe('--public-url', () => {
  it.each([
    [['--public-url', 'https://x.example'], /needs --http/],
    [['--public-url', 'https://x.example', '--guardian', '/tmp/s'], /conflict/],
    [['--http', '--public-url', 'http://x.example'], /takes an https origin/],
    [['--http', '--public-url', 'https://x.example/path'], /takes an https origin/],
  ])('rejects %j', async (args, message) => {
    const { code, stderr } = await run(args, { KORDN_TOKEN: 'x'.repeat(32) });
    expect(code).toBe(2);
    expect(stderr).toMatch(message);
  });

  it('refuses a short KORDN_TOKEN without creating the OAuth database', async () => {
    const data = tempDir();
    chmodSync(data, 0o700);
    const { code, stderr } = await run(['--http', '--port', '0', '--public-url', 'https://x.example', '--data', data], { KORDN_TOKEN: 'x'.repeat(31) });
    expect(code).toBe(1);
    expect(stderr).toMatch(/KORDN_TOKEN must be set/);
    expect(existsSync(join(data, 'oauth.sqlite'))).toBe(false);
  });

  it('turns OAuth on and keeps its database private', async () => {
    const data = tempDir();
    chmodSync(data, 0o700);
    const kordn = spawnCli(['--http', '--port', '0', '--public-url', 'https://x.example/', '--data', data], { KORDN_TOKEN: 'y'.repeat(32) });
    await kordn.waitForStderr(/kordn: OAuth on for https:\/\/x\.example\/mcp\n/);
    expect(statSync(join(data, 'oauth.sqlite')).mode & 0o777).toBe(0o600);
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
  });

  it.each([
    ['names another port', ['--port', '0', '--public-url', 'http://localhost:9'], true],
    ['names the default port of its scheme', ['--port', '0', '--public-url', 'http://127.0.0.1'], true],
    ['is not loopback', ['--port', '0', '--public-url', 'https://x.example'], false],
  ])('warns about a loopback --public-url only when it %s', async (_case, args, warns) => {
    const data = tempDir();
    chmodSync(data, 0o700);
    const kordn = spawnCli(['--http', ...args, '--data', data], { KORDN_TOKEN: 'y'.repeat(32) });
    await kordn.waitForStderr(/kordn: OAuth on for/);
    const port = new URL(args[3] as string).port || '80';
    const warning = `kordn: warning: --public-url port ${port} differs from --port 0; OAuth redirects will point at the wrong port\n`;
    if (warns) expect(kordn.stderr()).toContain(warning);
    else expect(kordn.stderr()).not.toContain('kordn: warning');
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
  });

  it('does not warn when a loopback --public-url names --port', async () => {
    const probe = createServer();
    await new Promise<void>((resolve) => probe.listen(0, '127.0.0.1', resolve));
    const { port } = probe.address() as { port: number };
    await new Promise<void>((resolve) => probe.close(() => resolve()));
    const data = tempDir();
    chmodSync(data, 0o700);
    const kordn = spawnCli(['--http', '--port', String(port), '--public-url', `http://localhost:${port}`, '--data', data], { KORDN_TOKEN: 'y'.repeat(32) });
    await kordn.waitForStderr(/kordn: OAuth on for/);
    expect(kordn.stderr()).not.toContain('kordn: warning');
    kordn.child.kill('SIGTERM');
    expect((await kordn.exited).code).toBe(0);
  });
});
