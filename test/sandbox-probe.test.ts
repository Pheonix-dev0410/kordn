import { spawn } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, readdirSync, readlinkSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from './fake-guardian.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { type ProbeParams, parseProbeOutput, probeScript } from '../src/sandbox-probe.js';
import { Policy } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const servers: Server[] = [];
const dirs: string[] = [];
afterEach(() => {
  for (const s of servers.splice(0)) s.close();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  return dir;
}

/** Run the probe the way the launcher does: script on stdin of a fresh node process. */
function runProbe(params: ProbeParams, env: NodeJS.ProcessEnv = {}): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['--input-type=module', '-'], { env, stdio: ['pipe', 'pipe', 'inherit'] });
    let out = '';
    child.stdout.setEncoding('utf8').on('data', (d: string) => (out += d));
    child.on('error', reject);
    child.on('close', () => resolve(out));
    child.stdin.end(probeScript(params));
  });
}

// The probe reads /proc, so its full report only exists on Linux.
const linuxOnly = process.platform === 'linux' ? it : it.skip;

const base: ProbeParams = { socketPath: '/nonexistent/kordn.sock', writeTargets: [], absentPaths: [], connect: [], timeoutMs: 1000 };

describe('isolation probe', () => {
  linuxOnly('runs standalone in a fresh node process and reports the process identity', async () => {
    const result = parseProbeOutput(await runProbe(base));
    expect(result).not.toBeNull();
    expect(result?.uid).toBe(process.getuid?.());
    expect(result?.status.NoNewPrivs).toMatch(/^[01]$/);
    expect(result?.mounts?.some((m) => m.mountPoint === '/')).toBe(true);
    expect(result?.mounts?.find((m) => m.mountPoint === '/proc')).toMatchObject({ root: '/', fsType: 'proc' });
    expect(result?.interfaces).toContain('lo');
    expect(result?.socket).toEqual({ connected: false, error: 'ENOENT', response: null });
  });

  linuxOnly('reports the namespace of each kind it lives in', async () => {
    const result = parseProbeOutput(await runProbe(base));
    expect(Object.keys(result?.namespaces ?? {}).sort()).toEqual(['cgroup', 'ipc', 'mnt', 'net', 'pid', 'user', 'uts']);
    for (const ns of ['cgroup', 'ipc', 'mnt', 'net', 'pid', 'user', 'uts']) {
      expect(result?.namespaces[ns], ns).toBe(readlinkSync(`/proc/self/ns/${ns}`));
    }
  });

  it('reports env var names but never their values', async () => {
    const stdout = await runProbe(base, { KORDN_PROBE_SECRET: 'hunter2-value' });
    expect(parseProbeOutput(stdout)?.env).toContain('KORDN_PROBE_SECRET');
    expect(stdout).not.toContain('hunter2-value');
  });

  it('makes one guardian call through the socket when asked', async () => {
    const dir = tempDir();
    const socketPath = join(dir, 'g.sock');
    servers.push(await serveGuardianSocket(createFakeGuardian({ policy }), policy.agentId, socketPath));
    const call = { tool: 'af_get_balance', args: { resourceId: policy.resourceId } };
    const result = parseProbeOutput(await runProbe({ ...base, socketPath, call }));
    expect(result?.socket).toMatchObject({ connected: true, error: null, response: { v: 1, ok: true, result: { currency: 'USD' } } });
  });

  it('only connects to the socket, without sending a frame, when no call is given', async () => {
    const dir = tempDir();
    const socketPath = join(dir, 'g.sock');
    let received = '';
    const server = createServer((s) => s.on('data', (d) => (received += String(d))));
    servers.push(server);
    await new Promise<void>((r) => server.listen(socketPath, r));
    const result = parseProbeOutput(await runProbe({ ...base, socketPath }));
    expect(result?.socket).toEqual({ connected: true, error: null, response: null });
    expect(received).toBe('');
  });

  it('tries writes and cleans up after a successful one', async () => {
    const dir = tempDir();
    const locked = join(dir, 'locked');
    mkdirSync(locked);
    chmodSync(locked, 0o500);
    const result = parseProbeOutput(await runProbe({ ...base, writeTargets: [dir, join(dir, 'missing'), locked] }));
    expect(result?.writes).toEqual([
      { path: dir, result: 'ok' },
      { path: join(dir, 'missing'), result: 'ENOENT' },
      { path: locked, result: 'EACCES' },
    ]);
    expect(readdirSync(dir)).toEqual(['locked']);
  });

  it('reports which paths exist', async () => {
    const dir = tempDir();
    writeFileSync(join(dir, 'present'), '');
    const result = parseProbeOutput(await runProbe({ ...base, absentPaths: [join(dir, 'present'), join(dir, 'gone')] }));
    expect(result?.paths).toEqual([
      { path: join(dir, 'present'), result: 'present' },
      { path: join(dir, 'gone'), result: 'ENOENT' },
    ]);
  });

  it('reports TCP connect outcomes', async () => {
    const listener = createServer((s) => s.destroy());
    servers.push(listener);
    await new Promise<void>((r) => listener.listen(0, '127.0.0.1', r));
    const open = (listener.address() as { port: number }).port;
    const closed = createServer();
    await new Promise<void>((r) => closed.listen(0, '127.0.0.1', r));
    const closedPort = (closed.address() as { port: number }).port;
    await new Promise((r) => closed.close(r));

    const connect = [
      { host: '127.0.0.1', port: open },
      { host: '127.0.0.1', port: closedPort },
    ];
    const result = parseProbeOutput(await runProbe({ ...base, connect }));
    expect(result?.connects).toEqual([
      { host: '127.0.0.1', port: open, result: 'connected' },
      { host: '127.0.0.1', port: closedPort, result: 'ECONNREFUSED' },
    ]);
  });

  it('rejects output that is not exactly a probe result', () => {
    expect(parseProbeOutput('')).toBeNull();
    expect(parseProbeOutput('not json')).toBeNull();
    expect(parseProbeOutput('{"uid":0}')).toBeNull();
  });
});
