import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';
import { homedir, networkInterfaces, tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { scanImage } from '../src/image-scan.js';
import { hardenedRunFlags, SANDBOX_SOCKET, socketFileMode } from '../src/sandbox.js';
import { type ProbeResult, parseProbeOutput, probeScript } from '../src/sandbox-probe.js';
import { Policy } from '../src/schema.js';
import { buildSandboxImage, DOCKER_TESTS, docker, dockerOk, hostUser, leftovers, removeImages, ROOT, testName } from './docker.js';

// #11 acceptance against a real Docker daemon: the image holds no secrets, and from inside
// the hardened container the guardian socket works and nothing else is reachable.

const policy = Policy.parse(policyJson);
const image = testName('sandbox');
const leaky = testName('leaky');
const dirs: string[] = [];
let probe: ProbeResult | null = null;
let canaryHits = 0;
let imageHasServer = false;

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  return dir;
}

const outbound = [
  { host: '1.1.1.1', port: 443 },
  { host: '8.8.8.8', port: 53 },
  { host: '2606:4700:4700::1111', port: 443 },
  { host: '172.17.0.1', port: 80 },
  { host: '169.254.169.254', port: 80 },
  ...Object.values(networkInterfaces())
    .flat()
    .filter((a) => a && !a.internal && a.family === 'IPv4')
    .map((a) => ({ host: a?.address ?? '', port: 80 })),
];

describe.skipIf(!DOCKER_TESTS)('sandbox image (Docker)', () => {
  beforeAll(async () => {
    await buildSandboxImage(image);
    const ls = await dockerOk(['run', '--rm', '--network', 'none', image, '-e', 'process.stdout.write(String(require("fs").existsSync("/app/dist/index.js")))']);
    imageHasServer = ls === 'true';

    // Host side: the fake guardian on a 0600 socket in a private dir, and a loopback canary
    // standing in for the admin UI.
    const dir = tempDir();
    const socketPath = join(dir, 'guardian.sock');
    const server = await serveGuardianSocket(createFakeGuardian({ policy }), policy.agentId, socketPath);
    chmodSync(socketPath, socketFileMode(false));
    const canary: Server = createServer((s) => {
      canaryHits++;
      s.destroy();
    });
    await new Promise<void>((r) => canary.listen(0, '127.0.0.1', r));
    const canaryPort = (canary.address() as { port: number }).port;

    const params = {
      socketPath: SANDBOX_SOCKET,
      call: { tool: 'af_get_balance', args: { resourceId: policy.resourceId } },
      writeTargets: ['/', '/etc', '/usr', '/var', '/app', '/run'],
      absentPaths: ['/var/run/docker.sock', '/run/docker.sock', homedir(), ...(process.env.SSH_AUTH_SOCK ? [process.env.SSH_AUTH_SOCK] : [])],
      connect: [...outbound, { host: '127.0.0.1', port: canaryPort }, { host: '::1', port: canaryPort }],
      timeoutMs: 2000,
    };
    try {
      const run = await docker(
        ['run', '--rm', '-i', '--name', testName('probe'), ...hardenedRunFlags({ socketPath, user: hostUser() }), image, '--input-type=module', '-'],
        probeScript(params),
      );
      probe = parseProbeOutput(run.stdout);
      if (!probe) throw new Error(`probe failed: ${run.code} ${run.stderr}`);
    } finally {
      server.close();
      canary.close();
    }
  }, 900_000);

  afterAll(async () => {
    await removeImages(image, leaky);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
    expect(await leftovers()).toEqual([]);
  }, 120_000);

  it('ships only the compiled app, production deps and the agent, as a non-root user, with no shell or npm', async () => {
    const out = await dockerOk([
      'run',
      '--rm',
      '--network',
      'none',
      image,
      '-e',
      'const fs = require("fs"); console.log(JSON.stringify({ app: fs.readdirSync("/app").sort(), sandbox: fs.readdirSync("/app/sandbox"), deps: fs.readdirSync("/app/node_modules").filter((d) => !d.startsWith(".")), uid: process.getuid(), shell: ["/bin/sh", "/bin/bash", "/busybox"].filter((p) => fs.existsSync(p)), npm: ["/usr/local/bin/npm", "/usr/bin/npm", "/nodejs/bin/npm"].filter((p) => fs.existsSync(p)) }))',
    ]);
    expect(JSON.parse(out)).toEqual({ app: ['dist', 'node_modules', 'package.json', 'sandbox'], sandbox: ['agent.mjs'], deps: ['zod'], uid: 65532, shell: [], npm: [] });
    const config = JSON.parse(await dockerOk(['image', 'inspect', '--format', '{{json .Config}}', image]));
    expect(config).toMatchObject({ User: '65532:65532', Entrypoint: ['/nodejs/bin/node'], Cmd: ['/app/sandbox/agent.mjs'] });
  });

  it('contains no secrets in any layer, env, label or history entry', async () => {
    const scan = await scanImage(image);
    expect(scan.layers).toBeGreaterThan(3);
    expect(scan.files).toBeGreaterThan(100);
    expect(scan.findings).toEqual([]);
  }, 300_000);

  it('the scanner catches secrets planted in an image', async () => {
    const ctx = tempDir();
    writeFileSync(join(ctx, '.env'), 'KORDN_TOKEN=abc\n');
    writeFileSync(join(ctx, 'notes.txt'), `ghp_${'a1B2c3D4e5'.repeat(4)}\n`);
    writeFileSync(join(ctx, 'Dockerfile'), `FROM ${image}\nCOPY .env /app/.env\nCOPY notes.txt /app/notes.txt\nENV NPM_TOKEN=npm-secret\n`);
    await dockerOk(['build', '-q', '-t', leaky, ctx], undefined, 300_000);
    const reasons = (await scanImage(leaky)).findings.map((f) => `${f.where.replace(/^.*:/, '')} ${f.reason}`);
    expect(reasons).toEqual(expect.arrayContaining(['app/.env env file', 'app/notes.txt GitHub token', 'env NPM_TOKEN secret-named assignment']));
  }, 300_000);

  it('keeps env files, VCS data, databases, deps and other junk out of the build context', async () => {
    const ctx = tempDir();
    const files = [
      'package.json',
      'package-lock.json',
      'tsconfig.json',
      'src/index.ts',
      'src/.env',
      'src/key.pem',
      '.env',
      '.env.local',
      '.envrc',
      '.git/config',
      '.npmrc',
      'node_modules/x/index.js',
      'dist/index.js',
      'kordn.sqlite',
      'kordn.sqlite-wal',
      'docs/design.docx',
      'test/a.test.ts',
      'sandbox/agent.mjs',
      'sandbox/notes.txt',
      '.worktrees/other/src/a.ts',
    ];
    for (const f of files) {
      mkdirSync(join(ctx, f, '..'), { recursive: true });
      writeFileSync(join(ctx, f), 'x');
    }
    writeFileSync(join(ctx, 'ctx.Dockerfile'), 'FROM scratch\nCOPY . /\n');
    cpSync(join(ROOT, 'sandbox/Dockerfile.dockerignore'), join(ctx, 'ctx.Dockerfile.dockerignore'));
    const out = tempDir();
    await dockerOk(['build', '-q', '-f', join(ctx, 'ctx.Dockerfile'), '--output', `type=local,dest=${out}`, ctx], undefined, 300_000);
    const seen = readdirSync(out, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => relative(out, join(e.parentPath, e.name)))
      .sort();
    expect(seen).toEqual(['package-lock.json', 'package.json', 'sandbox/agent.mjs', 'src/index.ts', 'tsconfig.json']);
  }, 300_000);

  describe('inside the hardened container', () => {
    it('reaches the guardian through the socket', () => {
      expect(probe?.socket).toMatchObject({
        connected: true,
        error: null,
        response: { v: 1, id: 'probe-1', ok: true, result: { currency: 'USD' } },
      });
    });

    it('has no network besides loopback', () => {
      expect(probe?.interfaces).toEqual(['lo']);
      expect(probe?.ipv4Routes).toEqual([]);
      expect(probe?.ipv6Routes?.every((i) => i === 'lo')).toBe(true);
      const out = probe?.connects.filter((c) => !['127.0.0.1', '::1'].includes(c.host)) ?? [];
      expect(out).toHaveLength(outbound.length);
      for (const c of out) expect(c.result, `${c.host}:${c.port}`).toBe('ENETUNREACH');
    });

    it("can't reach a service on the host's loopback", () => {
      const local = probe?.connects.filter((c) => ['127.0.0.1', '::1'].includes(c.host)) ?? [];
      expect(local).toHaveLength(2);
      for (const c of local) expect(c.result).not.toBe('connected');
      expect(canaryHits).toBe(0);
    });

    it('sees no docker socket, home dir or SSH agent', () => {
      for (const p of probe?.paths ?? []) expect(p.result, p.path).toBe('ENOENT');
      expect(probe?.env).not.toContain('SSH_AUTH_SOCK');
      expect(probe?.env.sort()).toEqual(['HOME', 'HOSTNAME', 'NODE_ENV', 'PATH', 'SSL_CERT_FILE']);
    });

    it('has only the guardian socket mounted from the host', () => {
      const docker = new Set(['/', '/proc', '/dev', '/dev/pts', '/sys', '/sys/fs/cgroup', '/dev/mqueue', '/dev/shm', '/tmp', '/etc/hostname', '/etc/hosts', '/etc/resolv.conf']);
      const extra = (probe?.mounts ?? [])
        .map((m) => m.mountPoint)
        .filter((p) => !docker.has(p) && !p.startsWith('/proc/') && !p.startsWith('/sys/'));
      expect(extra).toEqual([SANDBOX_SOCKET]);
    });

    it('has a read-only root filesystem', () => {
      for (const w of probe?.writes ?? []) expect(w.result, w.path).toBe('EROFS');
      expect(probe?.mounts?.find((m) => m.mountPoint === '/')?.options.split(',')).toContain('ro');
    });

    it('runs as the host user with no capabilities, no-new-privileges, seccomp and limits', () => {
      expect(`${probe?.uid}:${probe?.gid}`).toBe(hostUser());
      for (const cap of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb']) expect(probe?.status[cap], cap).toBe('0000000000000000');
      expect(probe?.status.NoNewPrivs).toBe('1');
      expect(probe?.status.Seccomp).toBe('2');
      expect(probe?.pidsMax).toBe('64');
      expect(probe?.memoryMax).toBe(String(512 * 1024 * 1024));
    });
  });

  it('the agent lists tools and makes a read call through kordn (needs the MCP server from #9)', async (ctx) => {
    if (!imageHasServer) ctx.skip();
    const dir = tempDir();
    const socketPath = join(dir, 'guardian.sock');
    const server = await serveGuardianSocket(createFakeGuardian({ policy }), policy.agentId, socketPath);
    chmodSync(socketPath, socketFileMode(false));
    try {
      const run = await docker(['run', '--rm', '-i', '--name', testName('agent'), ...hardenedRunFlags({ socketPath, user: hostUser() }), image]);
      expect(run.code, run.stderr).toBe(0);
      const lines = run.stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l));
      expect(lines[0].tools).toEqual(expect.arrayContaining(['af_get_balance', 'af_list_transactions', 'af_propose_transfer', 'af_get_transfer_status']));
      expect(lines[1]).toMatchObject({ step: 'tools/call', isError: false });
    } finally {
      server.close();
    }
  }, 120_000);

  it('the docker socket exists on this host, so its absence inside is meaningful', () => {
    expect(existsSync('/var/run/docker.sock') || existsSync('/run/docker.sock')).toBe(true);
  });
});
