#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { constants } from 'node:os';
import { parseArgs } from 'node:util';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { writeAdminFile } from './admin/runtime-file.js';
import type { Mode } from './admin/pages.js';
import { startAdminServer } from './admin/server.js';
import type { Guardian } from './guardian-api.js';
import { createGuardianClient } from './guardian-client.js';
import { MIN_TOKEN_LENGTH, serveHttp } from './http.js';
import { createMcpServer } from './mcp-server.js';
import { createOAuthServer, parsePublicUrl } from './oauth/server.js';
import { OAuthStore } from './oauth/store.js';
import { assertContainPlatform, formatReport, reapStaleContainers, runContain } from './sandbox.js';
import { Policy } from './schema.js';

// The kordn CLI and the only place arguments are parsed. stdout belongs to the MCP
// stdio transport, so everything human-readable goes to stderr.

const USAGE = `usage: kordn [--policy <path>] [--data <dir>] [--bank <path> [--live]] [--guardian <socket>] [--http [--port <n>] [--allowed-host <name>]... [--public-url <url>]] [--admin [--admin-port <n>]]
       kordn contain [--image <ref>] [--policy <path>] [--data <dir>] [--bank <path> [--live]] [--require-contain] [--admin [--admin-port <n>]] [-- <command>...]

  (default)              MCP over stdio, guardian in-process (Guard mode)
  --policy <path>        policy file; replaces the stored policy (default: examples/policy.json,
                         used only on first run)
  --data <dir>           where the ledger and mock bank live (default: ~/.local/state/kordn)
  --bank <path>          a real payment provider instead of the mock bank (stripe or paypal);
                         keys come from the environment, test mode only
  --live                 allow live provider keys (PayPal: use live, not sandbox): real money moves
  --guardian <socket>    forward every call to the guardian on this Unix socket (Contain mode)
  --http                 Streamable HTTP at http://127.0.0.1:<port>/mcp, needs KORDN_TOKEN
  --port <n>             HTTP port (default 3333)
  --allowed-host <name>  also accept this Host/Origin, e.g. a tunnel's public hostname
  --public-url <url>     turn on OAuth for apps like ChatGPT and claude.ai; the tunnel's https origin
  --admin                admin UI on 127.0.0.1; its URL and login token go to stderr and to
                         $XDG_RUNTIME_DIR/kordn/admin-<pid>.json
  --admin-port <n>       admin UI port (default 0: any free port)

  contain                run the agent in the sandbox (Linux, Docker), guardian in-process
  --image <ref>          sandbox image (default kordn-sandbox)
  --require-contain      don't run the agent unless every isolation check passed
  -- <command>...        the full command to run in the sandbox instead of the image's own`;

// node:sqlite prints an ExperimentalWarning on Node 24. stderr is for kordn's own messages, so
// drop that one and print the rest as Node would. The guardian is imported after this runs.
process.removeAllListeners('warning');
process.on('warning', (warning) => {
  if (warning.name === 'ExperimentalWarning' && /SQLite/.test(warning.message)) return;
  process.stderr.write(`${warning.name}: ${warning.message}\n`);
});

async function openGuardian(options: { data?: string; policy?: string; bank?: string; live: boolean }, policy: Policy) {
  const { defaultDataDir, openLocalGuardian } = await import('./local-guardian.js');
  const { loadBankConfig, openBank } = await import('./bank-config.js');
  const bank = options.bank === undefined ? undefined : loadBankConfig(options.bank);
  return openLocalGuardian(
    options.data ?? defaultDataDir(),
    policy,
    options.policy !== undefined,
    bank && ((enforced) => openBank(bank, enforced, process.env, options.live)),
  );
}

const DEFAULT_POLICY = new URL('../examples/policy.json', import.meta.url);
const DEFAULT_PORT = 3333;
const DEFAULT_IMAGE = 'kordn-sandbox';
// In Contain mode the guardian knows the agent from the socket; this label goes nowhere.
const SOCKET_BOUND_AGENT = 'socket-bound';

class UsageError extends Error {}

interface Options {
  policy?: string;
  data?: string;
  bank?: string;
  live: boolean;
  guardian?: string;
  http: boolean;
  port: number;
  allowedHosts: string[];
  publicUrl?: URL;
  admin: boolean;
  adminPort: number;
  help: boolean;
}

interface ContainOptions {
  policy?: string;
  data?: string;
  bank?: string;
  live: boolean;
  image: string;
  requireContain: boolean;
  /** Replaces the image's command when given. */
  agentCommand?: string[];
  admin: boolean;
  adminPort: number;
  help: boolean;
}

function parseOrUsage<T>(parse: () => T): T {
  try {
    return parse();
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
}

function portOption(value: string, flag: string): number {
  if (!/^\d{1,5}$/.test(value) || Number(value) > 65535) throw new UsageError(`${flag} must be 0-65535`);
  return Number(value);
}

function adminPortOption(values: { admin: boolean; 'admin-port'?: string }): number {
  if (values['admin-port'] === undefined) return 0;
  if (!values.admin) throw new UsageError('--admin-port needs --admin');
  return portOption(values['admin-port'], '--admin-port');
}

function publicUrlOption(value: string): URL {
  const url = parsePublicUrl(value);
  if (!url) throw new UsageError('--public-url takes an https origin, e.g. https://kordn.example.net (http only for localhost)');
  return url;
}

function parse(argv: string[]): Options {
  const { values } = parseOrUsage(() =>
    parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        policy: { type: 'string' },
        data: { type: 'string' },
        bank: { type: 'string' },
        live: { type: 'boolean', default: false },
        guardian: { type: 'string' },
        http: { type: 'boolean', default: false },
        port: { type: 'string' },
        'allowed-host': { type: 'string', multiple: true },
        'public-url': { type: 'string' },
        admin: { type: 'boolean', default: false },
        'admin-port': { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }),
  );
  if ((values.policy !== undefined || values.data !== undefined || values.bank !== undefined) && values.guardian !== undefined) {
    throw new UsageError('--policy, --data and --bank conflict with --guardian: in Contain mode the guardian owns them');
  }
  if (values.live && values.bank === undefined) throw new UsageError('--live needs --bank');
  if (values.admin && values.guardian !== undefined) {
    throw new UsageError('--admin and --guardian conflict: the admin UI runs where the guardian runs');
  }
  if (values['public-url'] !== undefined && values.guardian !== undefined) {
    throw new UsageError('--public-url and --guardian conflict: OAuth state lives where the guardian runs');
  }
  if (!values.http && values['public-url'] !== undefined) throw new UsageError('--public-url needs --http');
  if (!values.http && (values.port !== undefined || values['allowed-host'] !== undefined)) {
    throw new UsageError('--port and --allowed-host need --http');
  }
  return {
    policy: values.policy,
    data: values.data,
    bank: values.bank,
    live: values.live,
    guardian: values.guardian,
    http: values.http,
    port: values.port === undefined ? DEFAULT_PORT : portOption(values.port, '--port'),
    allowedHosts: (values['allowed-host'] ?? []).map(allowedHost),
    publicUrl: values['public-url'] === undefined ? undefined : publicUrlOption(values['public-url']),
    admin: values.admin,
    adminPort: adminPortOption(values),
    help: values.help,
  };
}

function parseContain(argv: string[]): ContainOptions {
  const { values, positionals, tokens } = parseOrUsage(() =>
    parseArgs({
      args: argv,
      strict: true,
      allowPositionals: true,
      tokens: true,
      options: {
        policy: { type: 'string' },
        data: { type: 'string' },
        bank: { type: 'string' },
        live: { type: 'boolean', default: false },
        image: { type: 'string' },
        'require-contain': { type: 'boolean', default: false },
        admin: { type: 'boolean', default: false },
        'admin-port': { type: 'string' },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }),
  );
  // Only `--` starts the agent command, so a mistyped flag can't silently become one.
  const terminator = tokens.findIndex((t) => t.kind === 'option-terminator');
  if (tokens.some((t, i) => t.kind === 'positional' && (terminator === -1 || i < terminator))) {
    throw new UsageError(`unexpected argument ${JSON.stringify(positionals[0])}; put the agent command after --`);
  }
  if (terminator !== -1 && positionals.length === 0) throw new UsageError('-- must be followed by the agent command');
  if (values.live && values.bank === undefined) throw new UsageError('--live needs --bank');
  return {
    policy: values.policy,
    data: values.data,
    bank: values.bank,
    live: values.live,
    image: values.image ?? DEFAULT_IMAGE,
    requireContain: values['require-contain'],
    agentCommand: positionals.length ? positionals : undefined,
    admin: values.admin,
    adminPort: adminPortOption(values),
    help: values.help,
  };
}

/**
 * Host checks compare the Host header's hostname exactly, so a value with a port, scheme,
 * path or wildcard, or an unbracketed IPv6 address, could never match. Refuse it rather
 * than ignore it.
 */
function allowedHost(value: string): string {
  const lower = value.toLowerCase();
  let hostname: string | undefined;
  try {
    hostname = new URL(`http://${lower}`).hostname;
  } catch {
    hostname = undefined;
  }
  const shape = /^[a-z0-9.-]+$/.test(lower) || /^\[[0-9a-f:.]+\]$/.test(lower);
  if (!shape || hostname !== lower) {
    throw new UsageError('--allowed-host takes a bare hostname, e.g. kordn.example.net or [::1]');
  }
  return hostname;
}

function loadPolicy(path: string | URL): Policy {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`invalid policy ${String(path)}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed = Policy.safeParse(raw);
  if (!parsed.success) throw new Error(`invalid policy ${String(path)}:\n${z.prettifyError(parsed.error)}`);
  return parsed.data;
}

interface RunningAdmin {
  port: number;
  setMode(mode: Mode): void;
  /** Also removes the admin file. Safe to call more than once. */
  close(): Promise<void>;
}

const MODE_LABEL: Record<Mode, string> = {
  checking: 'checking isolation',
  guard: 'guard mode',
  contain: 'contain mode',
  refused: 'refused',
};

/**
 * Starts the admin UI on the in-process guardian and tells the user where it is: on stderr,
 * and in the admin file for when an AI client spawned kordn and hides stderr. The file also
 * goes on any exit, even a forced one.
 */
async function startAdmin(guardian: Guardian, agentId: string, mode: Mode, port: number): Promise<RunningAdmin> {
  const admin = await startAdminServer({ guardian, agentId, mode, port });
  let file;
  try {
    file = writeAdminFile({ url: admin.url, token: admin.token, pid: process.pid, agentId });
  } catch (error) {
    await admin.close();
    throw error;
  }
  const remove = file.remove;
  process.on('exit', remove);
  process.stderr.write(
    `kordn: admin UI at ${admin.url} (${MODE_LABEL[mode]})\nkordn: admin login token: ${admin.token}\nkordn: both are also in ${file.path}\n`,
  );
  let closed: Promise<void> | undefined;
  return {
    port: Number(new URL(admin.url).port),
    setMode: (next) => {
      admin.setMode(next);
      process.stderr.write(`kordn: admin UI: ${MODE_LABEL[next]}${next === 'refused' ? ', shutting it down' : ''}\n`);
    },
    close: () => {
      remove();
      process.off('exit', remove);
      closed ??= admin.close();
      return closed;
    },
  };
}

const exitCodeFor = (signal: NodeJS.Signals) => 128 + constants.signals[signal];

/**
 * SIGINT, SIGTERM and SIGHUP (terminal closed or parent gone) run `stop` once. Another signal
 * while it runs exits at once: the user asked twice. The exit handlers still run, so the admin
 * file goes either way.
 */
function onStopSignal(stop: (signal: NodeJS.Signals) => void): void {
  let stopping = false;
  for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP'] as const) {
    process.on(signal, () => {
      if (stopping) {
        process.stderr.write(`kordn: ${signal} again, exiting before cleanup finished\n`);
        process.exit(exitCodeFor(signal));
      }
      stopping = true;
      stop(signal);
    });
  }
}

async function serve(options: Options, env: NodeJS.ProcessEnv): Promise<void> {
  let agentId: string;
  let handleCall: Guardian['handleCall'];
  let guardian: Guardian | undefined;
  if (options.guardian !== undefined) {
    agentId = SOCKET_BOUND_AGENT;
    handleCall = createGuardianClient(options.guardian);
  } else {
    // The agent identity is the launcher's policy, not the client's.
    const policy = loadPolicy(options.policy ?? DEFAULT_POLICY);
    const local = (await openGuardian(options, policy)).guardian;
    guardian = local;
    agentId = policy.agentId;
    handleCall = (agent, tool, args) => local.handleCall(agent, tool, args);
  }
  // Before anything OAuth-related is opened, so a bad token leaves no oauth.sqlite behind.
  const token = env.KORDN_TOKEN ?? '';
  if (options.http && options.publicUrl && token.length < MIN_TOKEN_LENGTH) {
    throw new Error(`KORDN_TOKEN must be set to a random secret of at least ${MIN_TOKEN_LENGTH} characters`);
  }
  const factory = () => createMcpServer({ agentId, handleCall });

  // Installed before anything starts, so a signal during startup still shuts down what's up.
  const closers: (() => Promise<void>)[] = [];
  if (options.http || options.admin) {
    onStopSignal(() => void Promise.allSettled(closers.map((close) => close())).finally(() => process.exit(0)));
  }
  // After openGuardian, which created the 0700 data dir; before the admin UI, which will share it.
  let oauthStore: OAuthStore | undefined;
  if (options.publicUrl && guardian) {
    const { defaultDataDir } = await import('./local-guardian.js');
    const store = OAuthStore.open(join(options.data ?? defaultDataDir(), 'oauth.sqlite'));
    oauthStore = store;
    closers.push(async () => store.close());
  }
  // Outside a sandbox there is nothing to check, so the admin UI says Guard.
  const admin = options.admin && guardian ? await startAdmin(guardian, agentId, 'guard', options.adminPort) : undefined;
  const closeAdmin = admin?.close;
  if (closeAdmin) closers.push(closeAdmin);

  if (options.http) {
    let http;
    try {
      const oauth =
        oauthStore && options.publicUrl && guardian
          ? createOAuthServer({
              store: oauthStore,
              publicUrl: options.publicUrl,
              ownerToken: token,
              audit: (event, app) => void guardian.recordOAuthEvent(event, app),
            })
          : undefined;
      http = await serveHttp({ factory, token, port: options.port, allowedHosts: options.allowedHosts, oauth });
    } catch (error) {
      await closeAdmin?.();
      oauthStore?.close();
      throw error;
    }
    const server = http;
    closers.push(() => server.close());
    process.stderr.write(`kordn: serving MCP at ${http.url}\n`);
    if (options.publicUrl) process.stderr.write(`kordn: OAuth on for ${options.publicUrl.origin}/mcp\n`);
    return;
  }

  const stdio = serveStdio(factory, { onerror: (error) => process.stderr.write(`kordn: ${error.message}\n`) });
  closers.push(() => stdio.close());
  if (closeAdmin) {
    // Without the admin UI, kordn exits when the client closes stdin because nothing else keeps
    // it alive. The admin server would, so it goes too; requests in flight still finish.
    const clientGone = () => void closeAdmin();
    process.stdin.once('end', clientGone).once('close', clientGone);
  }
}

/** Returns the exit code: the agent's, or 1 if it didn't run or didn't finish. */
async function contain(options: ContainOptions): Promise<number> {
  assertContainPlatform();
  const policy = loadPolicy(options.policy ?? DEFAULT_POLICY);
  // One guardian, one agent: the policy's.
  const local = await openGuardian(options, policy);
  const guardian = local.guardian;
  const controller = new AbortController();
  let stoppedBy: NodeJS.Signals | undefined;
  onStopSignal((signal) => {
    stoppedBy = signal;
    process.stderr.write(`kordn: ${signal}, stopping the sandbox\n`);
    controller.abort();
  });

  let admin: RunningAdmin | undefined;
  try {
    let reaped: string[];
    try {
      reaped = await reapStaleContainers({ signal: controller.signal });
    } catch (error) {
      if (controller.signal.aborted) throw error;
      throw new Error(`Docker is not available: ${error instanceof Error ? error.message : String(error)}`);
    }
    if (reaped.length) process.stderr.write(`kordn: removed ${reaped.length} sandbox container(s) left by a kordn that was killed\n`);
    // A signal during the reaper: don't start the admin UI (or print its token) only to stop it.
    controller.signal.throwIfAborted();
    // Up before the checks, so they probe its real port. It says "checking" until they're done,
    // and is up by the time the agent starts, so approvals work.
    if (options.admin) admin = await startAdmin(guardian, policy.agentId, 'checking', options.adminPort);
    const running = admin;
    const { agent } = await runContain({
      guardian,
      agentId: policy.agentId,
      image: options.image,
      agentCommand: options.agentCommand,
      requireContain: options.requireContain,
      signal: controller.signal,
      adminPort: running?.port,
      onReport: async (report) => {
        process.stderr.write(formatReport(report));
        if (!running) return;
        if (report.mode === 'contain' || !options.requireContain) return running.setMode(report.mode);
        running.setMode('refused');
        await running.close();
      },
    });
    // kordn's own failures exit 1, unless a stop signal came in meanwhile: then its code, as after an abort.
    const failure = () => (stoppedBy ? exitCodeFor(stoppedBy) : 1);
    if (!agent) {
      process.stderr.write('kordn: not running the agent: --require-contain needs every isolation check to pass\n');
      return failure();
    }
    if (agent.timedOut) {
      process.stderr.write('kordn: the agent timed out and was stopped\n');
      return failure();
    }
    if (agent.exitCode === null) {
      process.stderr.write(`kordn: the agent's docker exec was killed by ${agent.signal ?? 'a signal'}\n`);
      return failure();
    }
    return agent.exitCode;
  } catch (error) {
    if (stoppedBy) return exitCodeFor(stoppedBy);
    throw error;
  } finally {
    await admin?.close();
    local.close();
  }
}

async function main(argv: string[], env: NodeJS.ProcessEnv): Promise<void> {
  if (argv[0] === 'contain') {
    const options = parseContain(argv.slice(1));
    if (options.help) return void process.stdout.write(`${USAGE}\n`);
    process.exitCode = await contain(options);
    return;
  }
  const options = parse(argv);
  if (options.help) return void process.stdout.write(`${USAGE}\n`);
  await serve(options, env);
}

main(process.argv.slice(2), process.env).catch((error: unknown) => {
  const usage = error instanceof UsageError;
  process.stderr.write(`kordn: ${error instanceof Error ? error.message : String(error)}\n${usage ? `${USAGE}\n` : ''}`);
  process.exitCode = usage ? 2 : 1;
});
