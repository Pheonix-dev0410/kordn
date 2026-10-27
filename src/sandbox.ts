import { execFile, spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmodSync, mkdtempSync, readFileSync, readlinkSync, rmSync } from 'node:fs';
import { type AddressInfo, createServer, type Server, type Socket } from 'node:net';
import { homedir, networkInterfaces, tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Writable } from 'node:stream';
import { z } from 'zod';
import { AGENT_STDERR_PREFIX, AGENT_STDOUT_PREFIX, AgentLines } from './agent-output.js';
import type { Guardian } from './guardian-api.js';
import { serveGuardianSocket } from './guardian-socket.js';
import { evaluateIsolation, type IsolationExpectations, type IsolationResult, NAMESPACE_KINDS, probeTargets } from './sandbox-checks.js';
import { SANDBOX_SOCKET, SECURITY_OPTS, TMP_TMPFS_OPTIONS } from './sandbox-contract.js';
import { parseProbeOutput, probeScript } from './sandbox-probe.js';

// Contain mode: how the untrusted agent container is run, and
// runContain, which launches it and verifies isolation before the agent starts.
// The guardian socket is the only thing the container gets from the host.

export { SANDBOX_SOCKET } from './sandbox-contract.js';

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
    ...SECURITY_OPTS.flatMap((o) => ['--security-opt', o]),
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
    `/tmp:${TMP_TMPFS_OPTIONS}`,
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
// ---- kordn contain: launch the sandbox and verify isolation ----

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
  /**
   * Called with the coverage report before the agent starts, and awaited: the agent starts only
   * once it settles, and not at all if it throws. Default: print the report to stderr.
   */
  onReport?: (report: ContainReport) => void | Promise<void>;
  agentTimeoutMs?: number;
  /** Where the agent's stdout and stderr go, as they arrive. Default: this process's stdout and stderr. */
  agentOutput?: AgentOutput;
  /** Total agent output (stdout and stderr together) passed on; the rest is dropped. Default 16 MiB. */
  agentOutputLimitBytes?: number;
  /**
   * Stops the run: kills whichever docker command is running (the agent included), cleans up as
   * usual, and rejects with the abort reason or an AbortError.
   */
  signal?: AbortSignal;
  /** For tests. */
  platform?: NodeJS.Platform;
  docker?: string;
  runTimeoutMs?: number;
}

export interface ContainReport extends IsolationResult {
  platform: string;
}

export const AGENT_OUTPUT_LIMIT_BYTES = 16 * 1024 * 1024;

export interface AgentOutput {
  stdout: Writable;
  stderr: Writable;
}

export interface AgentRun {
  /** The agent's exit status. null if its docker exec was killed by a signal. */
  exitCode: number | null;
  /** The signal that killed the docker exec, if one did (SIGTERM after a timeout). */
  signal: NodeJS.Signals | null;
  /** kordn stopped it after agentTimeoutMs. */
  timedOut: boolean;
  /** Bytes the agent wrote to stdout and stderr together, including any that were dropped. */
  outputBytes: number;
  /** The output went past the limit and the rest was dropped. */
  truncated: boolean;
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

export interface RunDockerOptions {
  input?: string;
  timeoutMs?: number;
  /** Kills docker and rejects with an AbortError. */
  signal?: AbortSignal;
}

/** Runs docker with an argument array, never through a shell. */
export function runDocker(docker: string, args: string[], opts: RunDockerOptions = {}): Promise<DockerRun> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      docker,
      args,
      { encoding: 'utf8', timeout: opts.timeoutMs ?? 120_000, maxBuffer: 16 * 1024 * 1024, signal: opts.signal },
      (err, stdout, stderr) => {
        // A string code is a spawn, buffer or abort failure (ENOENT, maxBuffer, ABORT_ERR), not an exit status.
        if (err && typeof err.code === 'string') return reject(err);
        resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, stdout, stderr: err?.killed ? `${stderr}\n(timed out)` : stderr });
      },
    );
    child.stdin?.on('error', () => {});
    child.stdin?.end(opts.input ?? '');
  });
}

async function dockerOk(docker: string, args: string[], opts?: RunDockerOptions): Promise<string> {
  const r = await runDocker(docker, args, opts);
  if (r.code !== 0) throw new Error(`docker ${args[0]} failed (${r.code}): ${r.stderr.trim()}`);
  return r.stdout;
}

/**
 * Sinks given a permanent no-op error listener, so an error that arrives after a run (when its
 * own listener is gone) can't crash the process. Added once per sink.
 */
const guardedSinks = new WeakSet<Writable>();
const ignore = () => {};

/**
 * Runs the agent (docker exec) and passes its output to the sinks as it arrives, a line at a
 * time: every line prefixed (`agent | ` for stdout, `agent! | ` for stderr) and stripped of
 * control characters (AgentLines), since it shares a terminal with kordn's report. A line
 * start is shared by the two streams, as they usually end up on one terminal. Past
 * limitBytes of raw output in total the rest is still read, so the agent never blocks on a full
 * pipe, but dropped, with one kordn notice on the stderr sink. The limit is also what bounds
 * memory when a sink is slower than the agent. A sink that fails (e.g. EPIPE on stdout piped to
 * `head`) is given nothing more, and must not stop the run or the cleanup after it. If it's the
 * stdout sink, one kordn notice on the stderr sink says so.
 */
export function streamAgent(
  docker: string,
  args: string[],
  o: { output: AgentOutput; limitBytes: number; timeoutMs: number; signal?: AbortSignal },
): Promise<AgentRun> {
  return new Promise((resolve, reject) => {
    const streams = [
      { sink: o.output.stdout, lines: new AgentLines(AGENT_STDOUT_PREFIX) },
      { sink: o.output.stderr, lines: new AgentLines(AGENT_STDERR_PREFIX) },
    ] as const;
    const failed = new Set<Writable>();
    const fail = (sink: Writable) => {
      if (failed.has(sink)) return;
      failed.add(sink);
      if (sink === streams[0].sink) {
        const stderr = streams[1];
        write(stderr.sink, `${stderr.lines.breakLine()}kordn: stdout closed; dropping the agent's stdout\n`);
      }
    };
    const write = (sink: Writable, text: string) => {
      if (!text || failed.has(sink)) return;
      if (sink.destroyed || sink.writableEnded || sink.errored) return fail(sink);
      try {
        sink.write(text, (err) => err && fail(sink));
      } catch {
        fail(sink);
      }
    };
    // This run's listeners, removed when it ends; the permanent one only keeps errors harmless.
    const listeners = streams.map(({ sink }) => {
      if (!guardedSinks.has(sink)) {
        guardedSinks.add(sink);
        sink.on('error', ignore);
      }
      const onError = () => fail(sink);
      sink.on('error', onError);
      return () => sink.off('error', onError);
    });
    const detach = () => {
      for (const off of listeners) off();
    };

    const endLines = () => {
      for (const s of streams) write(s.sink, s.lines.end());
    };
    let outputBytes = 0;
    let passed = 0;
    let truncated = false;
    const forward = (s: (typeof streams)[number]) => (chunk: Buffer) => {
      outputBytes += chunk.length;
      if (truncated) return;
      const room = o.limitBytes - passed;
      const part = chunk.length <= room ? chunk : chunk.subarray(0, room);
      passed += part.length;
      const text = s.lines.push(part);
      if (text) {
        // Both streams usually end up on one terminal (or one file with 2>&1), so a line start
        // is shared: if the other stream is mid-line, end that line first. Otherwise this text
        // would continue the other stream's line, and a newline in it would start an unprefixed one.
        const other = s === streams[0] ? streams[1] : streams[0];
        write(other.sink, other.lines.breakLine());
        write(s.sink, text);
      }
      if (outputBytes > o.limitBytes) {
        truncated = true;
        endLines();
        write(o.output.stderr, `kordn: the agent's output passed ${o.limitBytes} bytes; dropping the rest\n`);
      }
    };

    const child = spawn(docker, args, { stdio: ['pipe', 'pipe', 'pipe'], signal: o.signal });
    let error: Error | undefined;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill();
    }, o.timeoutMs);
    child.stdout.on('data', forward(streams[0]));
    child.stderr.on('data', forward(streams[1]));
    child.stdin.on('error', () => {});
    child.stdin.end();
    child.on('error', (e) => {
      error = e;
      // A spawn failure (ENOENT) may never emit 'close'.
      if (child.pid === undefined) {
        clearTimeout(timer);
        detach();
        reject(e);
      }
    });
    child.on('close', (code, killedBy) => {
      clearTimeout(timer);
      if (!truncated) endLines();
      detach();
      if (error) return reject(error);
      resolve({ exitCode: code, signal: killedBy, timedOut, outputBytes, truncated });
    });
  });
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

/** This process's namespaces, the reference the sandbox must not share. */
export function launcherNamespaces(): Record<string, string> {
  const out: Record<string, string> = {};
  for (const ns of NAMESPACE_KINDS) {
    try {
      out[ns] = readlinkSync(`/proc/self/ns/${ns}`);
    } catch (e) {
      out[ns] = `error:${(e as NodeJS.ErrnoException).code ?? 'unknown'}`;
    }
  }
  return out;
}

export interface CheckContainerOptions {
  docker: string;
  container: string;
  /** `docker info` SecurityOptions wrapper: { SecurityOptions: string[] }. */
  info: unknown;
  expectations: IsolationExpectations;
  canary: Canary;
  signal?: AbortSignal;
}

/** Inspects a running container, probes it from inside, and evaluates every check. */
export async function checkContainer(o: CheckContainerOptions): Promise<IsolationResult> {
  const inspected = await runDocker(o.docker, ['inspect', '--type', 'container', o.container], { signal: o.signal });
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
    signal: o.signal,
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

const IMAGE = z.object({
  Id: z.string().regex(/^sha256:[0-9a-f]{64}$/),
  Config: z.object({
    Entrypoint: z.array(z.string()).nullable(),
    Cmd: z.array(z.string()).nullable(),
    Env: z.array(z.string()).nullable(),
  }),
});

/** A plain image reference or ID: no leading '-', no spaces or shell-ish characters. */
const IMAGE_REF = /^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,511}$/;

/**
 * Labels naming the launcher, so containers orphaned by a killed launcher can be reaped: its pid,
 * and the host boot id, PID-namespace inode and process start time that make the pid unambiguous.
 */
export const CONTAIN_LABEL = 'kordn.contain';
const IDENTITY_LABELS = ['', '.boot', '.pidns', '.start'].map((s) => `${CONTAIN_LABEL}${s}`);

export interface LauncherIdentity {
  pid: number;
  /** /proc/sys/kernel/random/boot_id: changes on every boot, differs between hosts. */
  boot: string;
  /** Inode of /proc/self/ns/pid: pids mean something only within one PID namespace. */
  pidns: string;
  /** Start time of the process in clock ticks since boot (/proc/<pid>/stat field 22). */
  start: string;
}

/** Start time of a process, null if there is no such process, undefined if it exists but can't be read. */
export function processStart(pid: number): string | null | undefined {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    // The command name (field 2) is in parentheses and may contain spaces.
    const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
    return fields[19];
  } catch {
    try {
      process.kill(pid, 0);
      return undefined;
    } catch (e) {
      // EPERM: it exists but belongs to someone else (e.g. hidden by hidepid).
      return (e as NodeJS.ErrnoException).code === 'EPERM' ? undefined : null;
    }
  }
}

export function launcherIdentity(): LauncherIdentity {
  return {
    pid: process.pid,
    boot: readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim(),
    pidns: /\[([0-9]+)\]/.exec(readlinkSync('/proc/self/ns/pid'))?.[1] ?? '',
    start: processStart(process.pid) ?? '',
  };
}

function identityLabels(me: LauncherIdentity): string[] {
  return [me.pid, me.boot, me.pidns, me.start].flatMap((v, i) => ['--label', `${IDENTITY_LABELS[i]}=${v}`]);
}

/**
 * From `docker ps` lines of "<id> <pid> <boot> <pidns> <start>": containers this host and PID
 * namespace launched whose launcher is gone (no such pid, or the pid now belongs to a process
 * started at another time). Anything else, including a launcher whose start time can't be read,
 * is left alone: a reaper elsewhere must never remove a live session.
 */
export function staleContainers(
  ps: string,
  self: { boot: string; pidns: string },
  startOf: (pid: number) => string | null | undefined,
): string[] {
  const stale: string[] = [];
  for (const line of ps.split('\n')) {
    const m = /^([0-9a-f]+) ([0-9]+) (\S+) ([0-9]+) ([0-9]+)$/.exec(line.trim());
    if (!m || m[3] !== self.boot || m[4] !== self.pidns) continue;
    const start = startOf(Number(m[2]));
    if (start === null || (start !== undefined && start !== m[5])) stale.push(m[1] ?? '');
  }
  return stale;
}

/**
 * Removes sandbox containers left behind by a launcher on this host that died before its cleanup
 * ran (for example SIGKILL). Returns the IDs removed.
 */
export async function reapStaleContainers(o: { docker?: string; signal?: AbortSignal } = {}): Promise<string[]> {
  const docker = o.docker ?? 'docker';
  const format = ['{{.ID}}', ...IDENTITY_LABELS.map((l) => `{{.Label "${l}"}}`)].join(' ');
  // An abort stops the listing. Removals, once started, finish: they're quick and the containers are orphans.
  const ps = await dockerOk(docker, ['ps', '--all', '--no-trunc', '--filter', `label=${CONTAIN_LABEL}`, '--format', format], {
    signal: o.signal,
  });
  const stale = staleContainers(ps, launcherIdentity(), processStart);
  for (const id of stale) await removeContainer(docker, id);
  return stale;
}

const LATE_SWEEP_MS = 1000;

async function sweepSession(docker: string, session: string): Promise<void> {
  const ps = await runDocker(docker, ['ps', '--all', '--quiet', '--no-trunc', '--filter', `label=${CONTAIN_LABEL}.session=${session}`]).catch(() => null);
  for (const leftover of ps?.stdout.split('\n').filter(Boolean) ?? []) await removeContainer(docker, leftover);
}

async function removeContainer(docker: string, id: string): Promise<void> {
  const r = await runDocker(docker, ['rm', '--force', id]).catch((e: Error) => ({ code: -1, stderr: e.message }));
  if (r.code !== 0) process.emitWarning(`kordn contain: could not remove container ${id}: ${r.stderr.trim()}`);
}

/** The parts of `docker info` the checks read: security options and the runtime definitions. */
export async function daemonInfo(docker = 'docker'): Promise<{ SecurityOptions?: unknown; Runtimes?: unknown }> {
  return JSON.parse(
    await dockerOk(docker, ['info', '--format', '{"SecurityOptions":{{json .SecurityOptions}},"Runtimes":{{json .Runtimes}}}']),
  );
}

/** Throws unless Contain mode can run on this platform (Linux only). */
export function assertContainPlatform(platform: NodeJS.Platform = process.platform): void {
  if (platform !== 'linux') {
    throw new Error(`Contain mode is not supported on ${platform}: it needs Linux with (rootless) Docker. Use Guard mode instead.`);
  }
}

export async function runContain(o: ContainOptions): Promise<ContainResult> {
  const platform = o.platform ?? process.platform;
  assertContainPlatform(platform);
  const { signal } = o;
  signal?.throwIfAborted();
  const docker = o.docker ?? 'docker';
  const name = o.name ?? `kordn-sandbox-${randomBytes(4).toString('hex')}`;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$/.test(name)) throw new Error(`invalid container name ${JSON.stringify(name)}`);
  if (!IMAGE_REF.test(o.image)) throw new Error(`invalid image reference ${JSON.stringify(o.image)}`);

  let info: { SecurityOptions?: unknown; Runtimes?: unknown };
  try {
    info = await daemonInfo(docker);
  } catch (e) {
    throw new Error(`Docker is not available: ${(e as Error).message}`);
  }
  signal?.throwIfAborted();
  const rootless = Array.isArray(info.SecurityOptions) && info.SecurityOptions.includes('name=rootless');
  // Resolve the tag once and run that exact image, so a re-tag in between can't swap it.
  const image = IMAGE.parse(JSON.parse(await dockerOk(docker, ['image', 'inspect', '--format', '{{json .}}', '--', o.image], { signal })));
  const entrypoint = image.Config.Entrypoint ?? [];
  if (entrypoint.length === 0) throw new Error(`image ${o.image} has no entrypoint (expected the node binary)`);
  const agentCommand = o.agentCommand ?? [...entrypoint, ...(image.Config.Cmd ?? [])];

  if ((await runDocker(docker, ['inspect', '--type', 'container', name], { signal })).code === 0) {
    throw new Error(`container name ${name} is already in use`);
  }

  const user = sandboxUser({ rootless, uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 });
  const session = randomBytes(8).toString('hex');
  // mkdtemp makes the directory 0700: only this user can reach the socket inside.
  const dir = mkdtempSync(join(tmpdir(), `${name}-`));
  const socketPath = join(dir, 'guardian.sock');
  const connections = new Set<Socket>();
  let server: Server | undefined;
  let canary: Canary | undefined;
  let id: string | undefined;
  // docker run timed out or was aborted: the daemon may still create the container.
  let runInterrupted = false;
  try {
    const flags = hardenedRunFlags({ socketPath, user });
    server = await serveGuardianSocket(o.guardian, o.agentId, socketPath);
    server.on('connection', (s: Socket) => {
      connections.add(s);
      s.on('close', () => connections.delete(s));
    });
    chmodSync(socketPath, socketFileMode(rootless));
    canary = await startCanary();
    signal?.throwIfAborted();

    const labels = [...identityLabels(launcherIdentity()), '--label', `${CONTAIN_LABEL}.session=${session}`];
    const created = await runDocker(docker, ['run', '--detach', '--name', name, ...labels, ...flags, image.Id, '-e', IDLE_SCRIPT], {
      timeoutMs: o.runTimeoutMs ?? 120_000,
      signal,
    }).catch((e: unknown) => {
      if (signal?.aborted) runInterrupted = true;
      throw e;
    });
    if (created.code === -1) {
      runInterrupted = true;
      throw new Error('docker run timed out');
    }
    if (created.code !== 0) throw new Error(`docker run failed (${created.code}): ${created.stderr.trim()}`);
    const started = created.stdout.trim();
    if (!/^[0-9a-f]{64}$/.test(started)) throw new Error(`docker run printed an unexpected container ID: ${JSON.stringify(started.slice(0, 80))}`);
    id = started;

    const expectations: IsolationExpectations = {
      socketPath,
      idleCommand: [...entrypoint, '-e', IDLE_SCRIPT],
      hostHome: homedir(),
      sshAuthSock: process.env.SSH_AUTH_SOCK || undefined,
      canaryPort: canary.port,
      adminPort: o.adminPort,
      dbPath: o.dbPath,
      hostAddresses: hostAddresses(),
      imageEnv: image.Config.Env ?? [],
      hostNamespaces: launcherNamespaces(),
      dockerSockets: await hostDockerSocketPaths(docker),
    };
    const result = await checkContainer({ docker, container: id, info, expectations, canary, signal });
    const report: ContainReport = { ...result, platform };
    if (o.onReport) await o.onReport(report);
    else process.stderr.write(formatReport(report));
    if (report.mode !== 'contain' && o.requireContain) return { report, agent: null };
    signal?.throwIfAborted();

    const agent = await streamAgent(docker, ['exec', '-i', id, ...agentCommand], {
      output: o.agentOutput ?? { stdout: process.stdout, stderr: process.stderr },
      limitBytes: o.agentOutputLimitBytes ?? AGENT_OUTPUT_LIMIT_BYTES,
      timeoutMs: o.agentTimeoutMs ?? 600_000,
      signal,
    });
    return { report, agent };
  } finally {
    if (id) await removeContainer(docker, id);
    else {
      // docker run failed after creating the container: find it by this session's label only.
      await sweepSession(docker, session);
      // After a timeout or abort the daemon may still be creating it: look once more a little later.
      if (runInterrupted) {
        await new Promise((r) => setTimeout(r, LATE_SWEEP_MS));
        await sweepSession(docker, session);
      }
    }
    // An agent that never hangs up would otherwise keep server.close() waiting forever.
    for (const s of connections) s.destroy();
    await canary?.close();
    await new Promise((resolve) => (server ? server.close(resolve) : resolve(undefined)));
    rmSync(dir, { recursive: true, force: true });
  }
}
