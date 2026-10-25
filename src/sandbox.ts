import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { type AddressInfo, createServer, type Server } from 'node:net';
import { homedir, networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import type { Guardian } from './guardian-api.js';
import { serveGuardianSocket } from './guardian-socket.js';
import { evaluateIsolation, type IsolationExpectations, type IsolationResult, probeTargets } from './sandbox-checks.js';
import { parseProbeOutput, probeScript, SANDBOX_SOCKET } from './sandbox-probe.js';

// Contain mode: how the untrusted agent container is run (design doc §9.1-9.2), and
// runContain, which launches it and verifies isolation before the agent starts (§9.3).
// The guardian socket is the only thing the container gets from the host.

export { SANDBOX_SOCKET } from './sandbox-probe.js';

/** The `nonroot` user of the distroless runtime image (sandbox/Dockerfile). */
const IMAGE_USER = '65532:65532';

export interface RunFlagOptions {
  /** Absolute host path of the guardian socket, inside a private (0700) directory. */
  socketPath: string;
  /** Numeric non-root uid:gid. */
  user: string;
}

export function hardenedRunFlags({ socketPath, user }: RunFlagOptions): string[] {
  // --mount is comma-separated key=value, so a comma or quote in the path could add options.
  if (!/^\/[^,"\n\r]+$/.test(socketPath)) throw new Error(`unsafe guardian socket path: ${JSON.stringify(socketPath)}`);
  const ids = /^([0-9]+):([0-9]+)$/.exec(user);
  if (!ids || Number(ids[1]) === 0 || Number(ids[2]) === 0) {
    throw new Error(`sandbox user must be a numeric non-root uid:gid, got ${JSON.stringify(user)}`);
  }
  return [
    '--network',
    'none',
    // No IPC namespace sharing and no /dev/shm: /tmp stays the only writable scratch space.
    '--ipc',
    'none',
    '--read-only',
    '--cap-drop',
    'ALL',
    '--security-opt',
    'no-new-privileges',
    '--pids-limit',
    '64',
    '--memory',
    '512m',
    // Same as --memory: no swap on top of the memory limit.
    '--memory-swap',
    '512m',
    '--cpus',
    '1',
    '--tmpfs',
    '/tmp:rw,nosuid,nodev,noexec,size=64m',
    '--user',
    user,
    '--mount',
    `type=bind,src=${socketPath},dst=${SANDBOX_SOCKET},readonly`,
  ];
}

/**
 * Rootful Docker: container uids are host uids, so running as the launching user lets it
 * connect to a 0600 socket nobody else can. Rootless Docker: container root is the host
 * user and every other container uid is a subordinate id, so a non-root container user
 * can't own the socket; it stays reachable only through the private 0700 directory.
 */
export function sandboxUser({ rootless, uid, gid }: { rootless: boolean; uid: number; gid: number }): string {
  return rootless ? IMAGE_USER : `${uid}:${gid}`;
}

export function socketFileMode(rootless: boolean): number {
  return rootless ? 0o666 : 0o600;
}

const unixPath = (endpoint: string | undefined) => (endpoint?.startsWith('unix://') ? endpoint.slice('unix://'.length) : undefined);

/**
 * Host paths where a Docker daemon socket may live: the rootful defaults, the socket named
 * by DOCKER_HOST or the current docker context, and the rootless default. None of them may
 * be visible inside the sandbox.
 */
export function dockerSocketPaths(o: { dockerHost?: string; contextHost?: string; xdgRuntimeDir?: string }): string[] {
  const paths = [
    '/var/run/docker.sock',
    '/run/docker.sock',
    unixPath(o.dockerHost),
    o.xdgRuntimeDir ? `${o.xdgRuntimeDir}/docker.sock` : undefined,
    unixPath(o.contextHost),
  ];
  return [...new Set(paths.filter((p): p is string => p !== undefined && p.startsWith('/')))];
}

/** The unix socket of the daemon `docker` talks to, from DOCKER_HOST or the current context. */
export function daemonSocketPath(docker = 'docker'): Promise<string | undefined> {
  const fromEnv = unixPath(process.env.DOCKER_HOST);
  if (fromEnv) return Promise.resolve(fromEnv);
  return new Promise((resolve) =>
    execFile(docker, ['context', 'inspect', '--format', '{{.Endpoints.docker.Host}}'], { encoding: 'utf8' }, (err, stdout) =>
      resolve(err ? undefined : unixPath(stdout.trim())),
    ),
  );
}

/** dockerSocketPaths for this host and environment. */
export async function hostDockerSocketPaths(docker = 'docker'): Promise<string[]> {
  return dockerSocketPaths({
    dockerHost: process.env.DOCKER_HOST,
    contextHost: await daemonSocketPath(docker),
    xdgRuntimeDir: process.env.XDG_RUNTIME_DIR,
  });
}
// ---- kordn contain: launch the sandbox and verify isolation (design doc §9.3) ----

/** PID 1 while the checks run. The agent starts only after them, via docker exec. */
export const IDLE_SCRIPT = 'setInterval(() => {}, 1 << 30)';

export interface ContainOptions {
  guardian: Guardian;
  /** Identity bound to the socket. The guardian never takes it from the agent. */
  agentId: string;
  image: string;
  /** Container name. Default kordn-sandbox-<random>. */
  name?: string;
  /** Full argv to run in the container. Default: the image's ENTRYPOINT + CMD. */
  agentCommand?: string[];
  /** Admin UI port on host loopback that must be unreachable. */
  adminPort?: number;
  /** Guardian database path that must not be visible inside. */
  dbPath?: string;
  /** Don't run the agent unless every check passed. */
  requireContain?: boolean;
  /** Called with the coverage report before the agent starts. Default: print it to stderr. */
  onReport?: (report: ContainReport) => void;
  agentTimeoutMs?: number;
  /** For tests. */
  platform?: NodeJS.Platform;
  docker?: string;
}

export interface ContainReport extends IsolationResult {
  platform: string;
}

export interface AgentRun {
  /** null if the agent was killed (timeout). */
  exitCode: number | null;
  stdout: string;
  stderr: string;
}

export interface ContainResult {
  report: ContainReport;
  /** null when requireContain refused to start it. */
  agent: AgentRun | null;
}

interface DockerRun {
  code: number;
  stdout: string;
  stderr: string;
}

/** Runs docker with an argument array, never through a shell. */
export function runDocker(docker: string, args: string[], opts: { input?: string; timeoutMs?: number } = {}): Promise<DockerRun> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      docker,
      args,
      { encoding: 'utf8', timeout: opts.timeoutMs ?? 120_000, maxBuffer: 16 * 1024 * 1024 },
      (err, stdout, stderr) => {
        // A string code is a spawn or buffer failure (ENOENT, maxBuffer), not an exit status.
        if (err && typeof err.code === 'string') return reject(err);
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout, stderr: err?.killed ? `${stderr}\n(timed out)` : stderr });
      },
    );
    child.stdin?.on('error', () => {});
    child.stdin?.end(opts.input ?? '');
  });
}

async function dockerOk(docker: string, args: string[], opts?: { input?: string; timeoutMs?: number }): Promise<string> {
  const r = await runDocker(docker, args, opts);
  if (r.code !== 0) throw new Error(`docker ${args[0]} failed (${r.code}): ${r.stderr.trim()}`);
  return r.stdout;
}

export interface Canary {
  port: number;
  hits(): number;
  close(): Promise<void>;
}

/**
 * A listener on host loopback standing in for the admin UI. If anything inside the sandbox
 * reaches it, the host sees the connection, whatever the probe reports.
 */
export async function startCanary(): Promise<Canary> {
  let hits = 0;
  const server = createServer((s) => {
    hits++;
    s.destroy();
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    port: (server.address() as AddressInfo).port,
    hits: () => hits,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** Non-loopback host addresses, to prove the sandbox can't reach the host over the network. */
export function hostAddresses(): string[] {
  return Object.values(networkInterfaces())
    .flat()
    .filter((a) => a !== undefined && !a.internal && !(a.family === 'IPv6' && a.address.startsWith('fe80')))
    .map((a) => a?.address ?? '');
}

export interface CheckContainerOptions {
  docker: string;
  container: string;
  /** `docker info` SecurityOptions wrapper: { SecurityOptions: string[] }. */
  info: unknown;
  expectations: IsolationExpectations;
  canary: Canary;
}

/** Inspects a running container, probes it from inside, and evaluates every check. */
export async function checkContainer(o: CheckContainerOptions): Promise<IsolationResult> {
  const inspected = await runDocker(o.docker, ['inspect', '--type', 'container', o.container]);
  let inspect: unknown = null;
  try {
    inspect = inspected.code === 0 ? JSON.parse(inspected.stdout) : null;
  } catch {
    inspect = null;
  }
  const node = o.expectations.idleCommand[0] ?? '';
  const probed = await runDocker(o.docker, ['exec', '-i', o.container, node, '--input-type=module', '-'], {
    input: probeScript(probeTargets(o.expectations)),
    timeoutMs: 60_000,
  });
  const probe = probed.code === 0 ? parseProbeOutput(probed.stdout) : null;
  return evaluateIsolation({ expectations: o.expectations, info: o.info, inspect, probe, canaryHits: o.canary.hits() });
}

export function formatReport(report: ContainReport): string {
  const failed = report.checks.filter((c) => !c.pass);
  const width = Math.max(...report.checks.map((c) => c.id.length));
  const lines = [
    `kordn contain: ${report.mode.toUpperCase()} mode (${report.platform}, image ${report.imageId ?? 'unknown'})`,
    ...report.checks.map((c) => `  ${c.pass ? 'ok  ' : 'FAIL'}  ${c.id.padEnd(width)}  ${c.detail}`),
  ];
  if (failed.length) {
    lines.push(
      `${failed.length} isolation check${failed.length === 1 ? '' : 's'} failed. Running in Guard mode: kordn still checks every call, but the agent is not contained.`,
    );
  }
  return `${lines.join('\n')}\n`;
}

const IMAGE_CONFIG = z.object({
  Entrypoint: z.array(z.string()).nullable(),
  Cmd: z.array(z.string()).nullable(),
  Env: z.array(z.string()).nullable(),
});

export async function runContain(o: ContainOptions): Promise<ContainResult> {
  const platform = o.platform ?? process.platform;
  if (platform !== 'linux') {
    throw new Error(`Contain mode is not supported on ${platform}: it needs Linux with (rootless) Docker. Use Guard mode instead.`);
  }
  const docker = o.docker ?? 'docker';
  const name = o.name ?? `kordn-sandbox-${randomBytes(4).toString('hex')}`;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(name)) throw new Error(`invalid container name ${JSON.stringify(name)}`);

  let securityOptions: unknown;
  try {
    securityOptions = JSON.parse(await dockerOk(docker, ['info', '--format', '{{json .SecurityOptions}}']));
  } catch (e) {
    throw new Error(`Docker is not available: ${(e as Error).message}`);
  }
  const info = { SecurityOptions: securityOptions };
  const rootless = Array.isArray(securityOptions) && securityOptions.includes('name=rootless');
  const image = IMAGE_CONFIG.parse(JSON.parse(await dockerOk(docker, ['image', 'inspect', '--format', '{{json .Config}}', o.image])));
  const entrypoint = image.Entrypoint ?? [];
  if (entrypoint.length === 0) throw new Error(`image ${o.image} has no entrypoint (expected the node binary)`);
  const agentCommand = o.agentCommand ?? [...entrypoint, ...(image.Cmd ?? [])];

  // The finally below force-removes the container by name, so it must be one we create.
  if ((await runDocker(docker, ['inspect', '--type', 'container', name])).code === 0) {
    throw new Error(`container name ${name} is already in use`);
  }

  const user = sandboxUser({ rootless, uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 });
  // mkdtemp makes the directory 0700: only this user can reach the socket inside.
  const dir = mkdtempSync(join(tmpdir(), `${name}-`));
  const socketPath = join(dir, 'guardian.sock');
  let server: Server | undefined;
  let canary: Canary | undefined;
  try {
    const flags = hardenedRunFlags({ socketPath, user });
    server = await serveGuardianSocket(o.guardian, o.agentId, socketPath);
    chmodSync(socketPath, socketFileMode(rootless));
    canary = await startCanary();

    await dockerOk(docker, ['run', '--detach', '--name', name, ...flags, o.image, '-e', IDLE_SCRIPT]);
    const expectations: IsolationExpectations = {
      socketPath,
      idleCommand: [...entrypoint, '-e', IDLE_SCRIPT],
      hostHome: homedir(),
      sshAuthSock: process.env.SSH_AUTH_SOCK || undefined,
      canaryPort: canary.port,
      adminPort: o.adminPort,
      dbPath: o.dbPath,
      hostAddresses: hostAddresses(),
      imageEnv: image.Env ?? [],
    };
    const result = await checkContainer({ docker, container: name, info, expectations, canary });
    const report: ContainReport = { ...result, platform };
    (o.onReport ?? ((r) => process.stderr.write(formatReport(r))))(report);
    if (report.mode !== 'contain' && o.requireContain) return { report, agent: null };

    const run = await runDocker(docker, ['exec', '-i', name, ...agentCommand], { timeoutMs: o.agentTimeoutMs ?? 600_000 });
    const killed = run.code === -1;
    return { report, agent: { exitCode: killed ? null : run.code, stdout: run.stdout, stderr: run.stderr } };
  } finally {
    await runDocker(docker, ['rm', '--force', name]).catch(() => undefined);
    await canary?.close();
    await new Promise((resolve) => (server ? server.close(resolve) : resolve(undefined)));
    rmSync(dir, { recursive: true, force: true });
  }
}
