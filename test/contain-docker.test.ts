import { chmodSync, existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import {
  type ContainReport,
  checkContainer,
  hardenedRunFlags,
  hostAddresses,
  IDLE_SCRIPT,
  runContain,
  socketFileMode,
  startCanary,
} from '../src/sandbox.js';
import type { CheckId, IsolationExpectations } from '../src/sandbox-checks.js';
import { Policy } from '../src/schema.js';
import { buildSandboxImage, DOCKER_TESTS, docker, dockerOk, hostUser, leftovers, removeImages, testName } from './docker.js';

// #12 against a real Docker daemon: runContain end to end, and every deliberately unsafe
// container setting actually launched and caught by the checks.

const policy = Policy.parse(policyJson);
const image = testName('contain');
const dirs: string[] = [];
let info: { SecurityOptions: string[] };
let rootless = false;
let entrypoint: string[] = [];
let imageEnv: string[] = [];
let imageHasServer = false;

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  return dir;
}

const failing = (r: { checks: { id: CheckId; pass: boolean }[] }) => r.checks.filter((c) => !c.pass).map((c) => c.id);
/** On this rootful host every report also fails `rootless`. */
const expectFailing = (r: { checks: { id: CheckId; pass: boolean }[]; mode: string }, ids: CheckId[]) => {
  expect(failing(r)).toEqual(rootless ? ids : ['rootless', ...ids]);
  expect(r.mode).toBe(failing(r).length ? 'guard' : 'contain');
};

const VALUE_FLAGS = new Set(['--network', '--cap-drop', '--security-opt', '--pids-limit', '--memory', '--memory-swap', '--cpus', '--tmpfs', '--user', '--mount']);
const drop = (flags: string[], ...names: string[]) =>
  flags.filter((f, i) => !names.includes(f) && !(i > 0 && names.includes(flags[i - 1] ?? '') && VALUE_FLAGS.has(flags[i - 1] ?? '')));
const set = (flags: string[], name: string, value: string) => flags.map((f, i) => (flags[i - 1] === name ? value : f));

interface Variant {
  edit: (flags: string[], ctx: { dir: string }) => string[];
  /** Host-side state the variant needs; returns its teardown. */
  setup?: (ctx: { dir: string }) => Promise<() => void>;
  expectations?: (ctx: { dir: string }) => Partial<IsolationExpectations>;
}

/** Launches the sandbox with edited flags and runs the same checks runContain does. */
async function launch(v: Variant) {
  const dir = tempDir();
  const socketPath = join(dir, 'guardian.sock');
  const server = await serveGuardianSocket(createFakeGuardian({ policy }), policy.agentId, socketPath);
  chmodSync(socketPath, socketFileMode(rootless));
  const canary = await startCanary();
  const name = testName('variant');
  const teardown = await v.setup?.({ dir });
  try {
    const flags = v.edit(hardenedRunFlags({ socketPath, user: hostUser() }), { dir });
    await dockerOk(['run', '--detach', '--name', name, ...flags, image, '-e', IDLE_SCRIPT]);
    const expectations: IsolationExpectations = {
      socketPath,
      idleCommand: [...entrypoint, '-e', IDLE_SCRIPT],
      hostHome: homedir(),
      canaryPort: canary.port,
      hostAddresses: hostAddresses(),
      imageEnv,
      ...v.expectations?.({ dir }),
    };
    return await checkContainer({ docker: 'docker', container: name, info, expectations, canary });
  } finally {
    await docker(['rm', '--force', name]);
    await canary.close();
    server.close();
    teardown?.();
  }
}

const dockerSock = ['/var/run/docker.sock', '/run/docker.sock'].find((p) => existsSync(p)) ?? '/var/run/docker.sock';

const variants: [string, Variant, CheckId[]][] = [
  ['the hardened flags', { edit: (f) => f }, []],
  ['bridge network', { edit: (f) => set(f, '--network', 'bridge') }, ['network']],
  ['host network', { edit: (f) => set(f, '--network', 'host') }, ['network', 'hostServicesUnreachable']],
  ['writable rootfs (non-root writes get EACCES)', { edit: (f) => drop(f, '--read-only') }, ['readOnlyRootfs']],
  ['docker.sock mounted', { edit: (f) => [...f, '--mount', `type=bind,src=${dockerSock},dst=/var/run/docker.sock`] }, ['onlyGuardianSocket']],
  ['a home dir mounted', { edit: (f, { dir }) => [...f, '--mount', `type=bind,src=${dir},dst=${homedir()},readonly`] }, ['onlyGuardianSocket']],
  // Root with every capability dropped has no CAP_DAC_OVERRIDE, so it can't open the 0600 socket either.
  ['root user', { edit: (f) => set(f, '--user', '0:0') }, ['nonRoot', 'guardianSocket']],
  ['no cap-drop', { edit: (f) => drop(f, '--cap-drop') }, ['capabilities']],
  ['no no-new-privileges', { edit: (f) => drop(f, '--security-opt') }, ['noNewPrivileges']],
  ['seccomp unconfined', { edit: (f) => [...f, '--security-opt', 'seccomp=unconfined'] }, ['seccomp']],
  ['--pid host', { edit: (f) => [...f, '--pid', 'host'] }, ['namespaces']],
  ['--ipc host', { edit: (f) => [...f, '--ipc', 'host'] }, ['namespaces']],
  ['no resource limits', { edit: (f) => drop(f, '--pids-limit', '--memory', '--memory-swap', '--cpus') }, ['resourceLimits']],
  ['a variable injected with -e', { edit: (f) => [...f, '-e', 'API_TOKEN=s3cret'] }, ['noHostEnv']],
  [
    'the SSH agent forwarded',
    {
      edit: (f, { dir }) => [...f, '-e', 'SSH_AUTH_SOCK=/ssh-agent.sock', '--mount', `type=bind,src=${join(dir, 'agent.sock')},dst=/ssh-agent.sock`],
      expectations: ({ dir }) => ({ sshAuthSock: join(dir, 'agent.sock') }),
      // A real listening socket standing in for ssh-agent, so the bind mount has a source.
      setup: async ({ dir }) => {
        const agent = createServer();
        await new Promise<void>((r) => agent.listen(join(dir, 'agent.sock'), r));
        return () => agent.close();
      },
    },
    ['onlyGuardianSocket', 'noHostEnv'],
  ],
  ['a user that cannot open the 0600 socket', { edit: (f) => set(f, '--user', '4242:4242') }, ['guardianSocket']],
];

describe.skipIf(!DOCKER_TESTS)('kordn contain (Docker)', () => {
  beforeAll(async () => {
    await buildSandboxImage(image);
    info = { SecurityOptions: JSON.parse(await dockerOk(['info', '--format', '{{json .SecurityOptions}}'])) };
    rootless = info.SecurityOptions.includes('name=rootless');
    const config = JSON.parse(await dockerOk(['image', 'inspect', '--format', '{{json .Config}}', image]));
    entrypoint = config.Entrypoint;
    imageEnv = config.Env;
    imageHasServer = (await dockerOk(['run', '--rm', '--network', 'none', image, '-e', 'process.stdout.write(String(require("fs").existsSync("/app/dist/index.js")))'])) === 'true';
  }, 900_000);

  afterAll(async () => {
    await removeImages(image);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
    expect(await leftovers()).toEqual([]);
  }, 120_000);

  describe('runContain', () => {
    const guardian = () => createFakeGuardian({ policy });
    const agentCommand = () => [...entrypoint, '-e', 'console.log("agent ran as", process.getuid())'];

    it('reports honestly, prints before the agent runs, runs the agent, and cleans up', async () => {
      const name = testName('run');
      const events: string[] = [];
      let report: ContainReport | undefined;
      const result = await runContain({
        guardian: guardian(),
        agentId: policy.agentId,
        image,
        name,
        agentCommand: agentCommand(),
        onReport: (r) => {
          report = r;
          events.push('report');
        },
      });
      expect(events).toEqual(['report']);
      expect(result.report).toBe(report);
      expectFailing(result.report, []);
      expect(result.report.mode).toBe(rootless ? 'contain' : 'guard');
      expect(result.report.platform).toBe('linux');
      expect(result.report.imageId).toMatch(/^sha256:[0-9a-f]{64}$/);
      expect(result.agent).toEqual({ exitCode: 0, stdout: `agent ran as ${process.getuid?.()}\n`, stderr: '' });
      expect((await docker(['inspect', '--type', 'container', name])).code).not.toBe(0);
      expect(readdirSync(tmpdir()).filter((d) => d.startsWith(`${name}-`))).toEqual([]);
    }, 120_000);

    it('requireContain refuses to start the agent on a Guard result', async (ctx) => {
      if (rootless) ctx.skip();
      const name = testName('require');
      const result = await runContain({
        guardian: guardian(),
        agentId: policy.agentId,
        image,
        name,
        agentCommand: agentCommand(),
        requireContain: true,
        onReport: () => {},
      });
      expect(result.report.mode).toBe('guard');
      expect(result.agent).toBeNull();
      expect((await docker(['inspect', '--type', 'container', name])).code).not.toBe(0);
    }, 120_000);

    it('proves a listening admin UI port and the guardian DB path are out of reach', async () => {
      // Something really listens on the admin port; the hardened sandbox still can't reach it.
      const admin = createServer((s) => s.destroy());
      await new Promise<void>((r) => admin.listen(0, '127.0.0.1', r));
      try {
        const port = (admin.address() as { port: number }).port;
        const result = await runContain({
          guardian: guardian(),
          agentId: policy.agentId,
          image,
          name: testName('admin'),
          agentCommand: agentCommand(),
          adminPort: port,
          dbPath: join(homedir(), '.kordn', 'kordn.sqlite'),
          onReport: () => {},
        });
        expectFailing(result.report, []);
        expect(result.report.checks.find((c) => c.id === 'hostServicesUnreachable')?.detail).toContain(`admin UI port ${port}`);
      } finally {
        admin.close();
      }
    }, 120_000);

    it('runs the default agent through kordn (needs the MCP server from #9)', async (ctx) => {
      if (!imageHasServer) ctx.skip();
      const result = await runContain({ guardian: guardian(), agentId: policy.agentId, image, name: testName('agent'), onReport: () => {} });
      expect(result.agent?.exitCode, result.agent?.stderr).toBe(0);
    }, 120_000);
  });

  describe('unsafe settings are caught', () => {
    for (const [name, variant, expected] of variants) {
      it(`${name}: ${expected.length ? `fails ${expected.join(' + ')}` : 'passes everything but rootless'}`, async () => {
        expectFailing(await launch(variant), expected);
      }, 120_000);
    }
  });
});
