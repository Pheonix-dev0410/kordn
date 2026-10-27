#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { constants } from 'node:os';
import { parseArgs } from 'node:util';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { writeAdminFile } from './admin/runtime-file.js';
import type { Mode } from './admin/pages.js';
import { type ConnectedApps, startAdminServer } from './admin/server.js';
import type { Guardian } from './guardian-api.js';
import { createGuardianClient } from './guardian-client.js';
import { MIN_TOKEN_LENGTH, serveHttp } from './http.js';
import { createMcpServer } from './mcp-server.js';
import { createOAuthServer, parsePublicUrl } from './oauth/server.js';
import type { OAuthStore } from './oauth/store.js';
import { assertContainPlatform, formatReport, reapStaleContainers, runContain } from './sandbox.js';
import { Policy } from './schema.js';
import { startNgrok, startQuickTunnel } from './tunnel.js';

// The kordn CLI and the only place arguments are parsed. stdout belongs to the MCP
// stdio transport, so everything human-readable goes to stderr.

const USAGE = `usage: kordn [--policy <path>] [--data <dir>] [--bank <path> [--live]] [--guardian <socket>] [--http [--port <n>] [--allowed-host <name>]... [--public-url <url> | --tunnel | --ngrok <domain>]] [--admin [--admin-port <n>]]
       kordn setup [--data <dir>]
       kordn contain [--image <ref>] [--policy <path>] [--data <dir>] [--bank <path> [--live]] [--require-contain] [--admin [--admin-port <n>]] [-- <command>...]

  (default)              MCP over stdio, guardian in-process (Guard mode)
  setup                  choose the account to guard (mock, PayPal, Stripe, Plaid), test or live,
                         its keys, payees and limits; saved in ~/.config/kordn and used whenever
                         --policy and --bank aren't given
  --policy <path>        policy file; replaces the stored policy (default: what kordn setup saved,
                         else examples/policy.json, used only on first run)
  --data <dir>           where the ledger and mock bank live (default: ~/.local/state/kordn)
  --bank <path>          a real provider instead of the mock bank (stripe, paypal, or plaid to
                         read a bank account); keys come from the environment; test mode unless
                         --live or the file has "live": true
  --live                 allow live provider keys (PayPal: use live, not sandbox): real money moves
  --guardian <socket>    forward every call to the guardian on this Unix socket (Contain mode)
  --http                 Streamable HTTP at http://127.0.0.1:<port>/mcp; the token is KORDN_TOKEN, or
                         one kordn makes and keeps in <data>/http-token
  --port <n>             HTTP port (default 3333)
  --allowed-host <name>  also accept this Host/Origin, e.g. a tunnel's public hostname
  --public-url <url>     turn on OAuth for apps like ChatGPT and claude.ai; the tunnel's https origin
  --tunnel               start a free Cloudflare quick tunnel (needs cloudflared) and use its URL
                         as --public-url; it changes on every start
  --ngrok <domain>       start ngrok on your static domain (e.g. name.ngrok-free.app) and use it as
                         --public-url; it stays the same, and ngrok is restarted if it stops
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

/** The account to guard: --policy and --bank if given, else what `kordn setup` saved, else the example. */
async function account(options: { policy?: string; bank?: string }, env: NodeJS.ProcessEnv) {
  const saved = options.policy === undefined && options.bank === undefined ? (await import('./setup.js')).savedSetup(env) : null;
  if (saved) return { policy: loadPolicy(saved.policyPath), bank: saved.bankPath, env: saved.env, replace: false };
  return { policy: loadPolicy(options.policy ?? DEFAULT_POLICY), bank: options.bank, env, replace: options.policy !== undefined };
}

async function openGuardian(options: { data?: string; live: boolean }, chosen: Awaited<ReturnType<typeof account>>) {
  const { defaultDataDir, openLocalGuardian } = await import('./local-guardian.js');
  const { isLive, loadBankConfig, openBank } = await import('./bank-config.js');
  const bank = chosen.bank === undefined ? undefined : loadBankConfig(chosen.bank);
  const local = await openLocalGuardian(
    options.data ?? defaultDataDir(),
    chosen.policy,
    chosen.replace,
    bank && ((enforced) => openBank(bank, enforced, chosen.env, options.live)),
  );
  const live = bank !== undefined && isLive(bank, chosen.env, options.live);
  if (live) {
    process.stderr.write(bank.provider === 'plaid'
      ? 'kordn: LIVE: reading your real bank account through Plaid\n'
      : `kordn: LIVE: guarding your real ${bank.provider === 'paypal' ? 'PayPal' : 'Stripe'} account; payments move real money\n`);
  }
  return { ...local, live };
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
  tunnel: boolean;
  ngrok?: URL;
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

/** The static domain, bare (name.ngrok-free.app) or as an https origin. */
function ngrokOption(value: string): URL {
  const url = parsePublicUrl(/^https?:\/\//.test(value) ? value : `https://${value}`);
  if (!url || url.protocol !== 'https:') throw new UsageError('--ngrok takes your ngrok domain, e.g. name.ngrok-free.app');
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
        tunnel: { type: 'boolean', default: false },
        ngrok: { type: 'string' },
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
  if (values.tunnel) {
    if (!values.http) throw new UsageError('--tunnel needs --http');
    if (values['public-url'] !== undefined) throw new UsageError('--tunnel and --public-url conflict: the tunnel gives the public URL');
    if (values.guardian !== undefined) throw new UsageError('--tunnel and --guardian conflict: OAuth state lives where the guardian runs');
    if (values.port === '0') throw new UsageError('--tunnel needs a fixed --port');
  }
  if (values.ngrok !== undefined) {
    if (!values.http) throw new UsageError('--ngrok needs --http');
    if (values.tunnel) throw new UsageError('--ngrok and --tunnel conflict: choose one');
    if (values['public-url'] !== undefined) throw new UsageError('--ngrok and --public-url conflict: ngrok gives the public URL');
    if (values.guardian !== undefined) throw new UsageError('--ngrok and --guardian conflict: OAuth state lives where the guardian runs');
    if (values.port === '0') throw new UsageError('--ngrok needs a fixed --port');
  }
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
    tunnel: values.tunnel,
    ngrok: values.ngrok === undefined ? undefined : ngrokOption(values.ngrok),
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
async function startAdmin(guardian: Guardian, agentId: string, mode: Mode, port: number, apps?: ConnectedApps, live?: boolean): Promise<RunningAdmin> {
  const admin = await startAdminServer({ guardian, agentId, mode, port, apps, live });
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

/** A tunnel may map any port, but a loopback public URL is reached directly, so its port has to be kordn's. */
function warnOnPortMismatch(publicUrl: URL, port: number): void {
  if (publicUrl.hostname !== 'localhost' && publicUrl.hostname !== '127.0.0.1') return;
  const publicPort = Number(publicUrl.port || (publicUrl.protocol === 'https:' ? 443 : 80));
  if (publicPort !== port) {
    process.stderr.write(`kordn: warning: --public-url port ${publicPort} differs from --port ${port}; OAuth redirects will point at the wrong port\n`);
  }
}

/** The --http token kept in the data dir, made on first use. */
function savedToken(path: string): string {
  try {
    return readFileSync(path, 'utf8').trim();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
  const token = randomBytes(32).toString('hex');
  writeFileSync(path, `${token}\n`, { mode: 0o600, flag: 'wx' });
  return token;
}

async function serve(options: Options, env: NodeJS.ProcessEnv): Promise<void> {
  let agentId: string;
  let handleCall: Guardian['handleCall'];
  let guardian: Guardian | undefined;
  let resourceId: string | undefined;
  let live = false;
  if (options.guardian !== undefined) {
    agentId = SOCKET_BOUND_AGENT;
    handleCall = createGuardianClient(options.guardian);
  } else {
    // The agent identity is the launcher's policy, not the client's.
    const chosen = await account(options, env);
    const policy = chosen.policy;
    const opened = await openGuardian(options, chosen);
    const local = opened.guardian;
    live = opened.live;
    guardian = local;
    agentId = policy.agentId;
    resourceId = policy.resourceId;
    handleCall = (agent, tool, args) => local.handleCall(agent, tool, args);
  }
  // In Contain mode the guardian owns the data dir.
  const dataDir = guardian ? (options.data ?? (await import('./local-guardian.js')).defaultDataDir()) : undefined;
  // Without KORDN_TOKEN, --http makes a token and keeps it, so it stays the same across restarts.
  let token = env.KORDN_TOKEN ?? '';
  const tokenFile = options.http && env.KORDN_TOKEN === undefined && dataDir ? join(dataDir, 'http-token') : undefined;
  if (tokenFile) token = savedToken(tokenFile);
  // Before anything OAuth-related is opened, so a bad token leaves no oauth.sqlite behind.
  if (options.http && (options.publicUrl || options.tunnel) && token.length < MIN_TOKEN_LENGTH) {
    throw new Error(`KORDN_TOKEN must be set to a random secret of at least ${MIN_TOKEN_LENGTH} characters`);
  }
  const factory = () => createMcpServer({ agentId, handleCall, resourceId });

  // Installed before anything starts, so a signal during startup still shuts down what's up.
  const closers: (() => Promise<void>)[] = [];
  if (options.http || options.admin) {
    onStopSignal(() => void Promise.allSettled(closers.map((close) => close())).finally(() => process.exit(0)));
  }
  let publicUrl = options.publicUrl;
  if (options.tunnel || options.ngrok) {
    const tunnel = options.ngrok ? await startNgrok(options.port, options.ngrok) : await startQuickTunnel(options.port);
    closers.push(async () => tunnel.close());
    publicUrl = tunnel.url;
  }
  // After openGuardian, which created the 0700 data dir; before the admin UI, which will share it.
  let oauthStore: OAuthStore | undefined;
  if (publicUrl && dataDir) {
    // Imported here, after the warning filter above: it loads node:sqlite.
    const store = (await import('./oauth/store.js')).OAuthStore.open(join(dataDir, 'oauth.sqlite'));
    oauthStore = store;
    closers.push(async () => store.close());
  }
  // Outside a sandbox there is nothing to check, so the admin UI says Guard.
  const admin = options.admin && guardian ? await startAdmin(guardian, agentId, 'guard', options.adminPort, oauthStore && {
        list: () => oauthStore.listApps(),
        revoke: (clientId) => oauthStore.revokeClient(clientId),
      }, live)
    : undefined;
  const closeAdmin = admin?.close;
  if (closeAdmin) closers.push(closeAdmin);

  if (options.http) {
    let http;
    try {
      const oauth =
        oauthStore && publicUrl && guardian
          ? createOAuthServer({
              store: oauthStore,
              publicUrl,
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
    if (publicUrl) {
      warnOnPortMismatch(publicUrl, options.port);
      process.stderr.write(`kordn: OAuth on for ${publicUrl.origin}/mcp\n`);
    }
    if (tokenFile) process.stderr.write(`kordn: token ${token} (kept in ${tokenFile}; KORDN_TOKEN overrides it)\n`);
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
  const chosen = await account(options, process.env);
  const policy = chosen.policy;
  // One guardian, one agent: the policy's.
  const local = await openGuardian(options, chosen);
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
    if (options.admin) admin = await startAdmin(guardian, policy.agentId, 'checking', options.adminPort, undefined, local.live);
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
  if (argv[0] === 'setup') {
    const { values } = parseOrUsage(() => parseArgs({ args: argv.slice(1), strict: true, options: { data: { type: 'string' }, help: { type: 'boolean', short: 'h', default: false } } }));
    if (values.help) return void process.stdout.write(`${USAGE}\n`);
    return (await import('./setup.js')).runSetup({ data: values.data }, env);
  }
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
