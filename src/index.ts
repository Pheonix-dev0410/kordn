#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { serveStdio } from '@modelcontextprotocol/server/stdio';
import { z } from 'zod';
import { createFakeGuardian } from './fake-guardian.js';
import type { Guardian } from './guardian-api.js';
import { createGuardianClient } from './guardian-client.js';
import { serveHttp } from './http.js';
import { createMcpServer } from './mcp-server.js';
import { Policy } from './schema.js';

// The kordn CLI and the only place arguments are parsed. stdout belongs to the MCP
// stdio transport, so everything human-readable goes to stderr.

const USAGE = `usage: kordn [--policy <path> | --guardian <socket>] [--http [--port <n>] [--allowed-host <name>]...]

  (default)              MCP over stdio, guardian in-process (Guard mode)
  --policy <path>        policy file (default: examples/policy.json in the kordn package)
  --guardian <socket>    forward every call to the guardian on this Unix socket (Contain mode)
  --http                 Streamable HTTP at http://127.0.0.1:<port>/mcp, needs KORDN_TOKEN
  --port <n>             HTTP port (default 3333)
  --allowed-host <name>  also accept this Host/Origin, e.g. a tunnel's public hostname`;

const DEFAULT_POLICY = new URL('../examples/policy.json', import.meta.url);
const DEFAULT_PORT = 3333;
// In Contain mode the guardian knows the agent from the socket; this label goes nowhere.
const SOCKET_BOUND_AGENT = 'socket-bound';

class UsageError extends Error {}

interface Options {
  policy?: string;
  guardian?: string;
  http: boolean;
  port: number;
  allowedHosts: string[];
  help: boolean;
}

function parse(argv: string[]): Options {
  let values;
  try {
    ({ values } = parseArgs({
      args: argv,
      strict: true,
      allowPositionals: false,
      options: {
        policy: { type: 'string' },
        guardian: { type: 'string' },
        http: { type: 'boolean', default: false },
        port: { type: 'string' },
        'allowed-host': { type: 'string', multiple: true },
        help: { type: 'boolean', short: 'h', default: false },
      },
    }));
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }
  if (values.policy !== undefined && values.guardian !== undefined) {
    throw new UsageError('--policy and --guardian conflict: in Contain mode the guardian owns the policy');
  }
  if (!values.http && (values.port !== undefined || values['allowed-host'] !== undefined)) {
    throw new UsageError('--port and --allowed-host need --http');
  }
  let port = DEFAULT_PORT;
  if (values.port !== undefined) {
    if (!/^\d{1,5}$/.test(values.port) || Number(values.port) > 65535) throw new UsageError('--port must be 0-65535');
    port = Number(values.port);
  }
  return {
    policy: values.policy,
    guardian: values.guardian,
    http: values.http,
    port,
    allowedHosts: values['allowed-host'] ?? [],
    help: values.help,
  };
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

async function main(argv: string[], env: NodeJS.ProcessEnv): Promise<void> {
  const options = parse(argv);
  if (options.help) {
    process.stdout.write(`${USAGE}\n`);
    return;
  }

  let agentId: string;
  let handleCall: Guardian['handleCall'];
  if (options.guardian !== undefined) {
    agentId = SOCKET_BOUND_AGENT;
    handleCall = createGuardianClient(options.guardian);
  } else {
    // Until the real guardian (#6) lands. The agent identity is the launcher's policy, not the client's.
    const policy = loadPolicy(options.policy ?? DEFAULT_POLICY);
    const guardian = createFakeGuardian({ policy });
    agentId = policy.agentId;
    handleCall = (agent, tool, args) => guardian.handleCall(agent, tool, args);
  }
  const factory = () => createMcpServer({ agentId, handleCall });

  if (options.http) {
    const token = env.KORDN_TOKEN ?? '';
    const http = await serveHttp({ factory, token, port: options.port, allowedHosts: options.allowedHosts });
    process.stderr.write(`kordn: serving MCP at ${http.url}\n`);
    for (const signal of ['SIGINT', 'SIGTERM'] as const) {
      process.once(signal, () => void http.close().finally(() => process.exit(0)));
    }
    return;
  }

  serveStdio(factory, { onerror: (error) => process.stderr.write(`kordn: ${error.message}\n`) });
}

main(process.argv.slice(2), process.env).catch((error: unknown) => {
  const usage = error instanceof UsageError;
  process.stderr.write(`kordn: ${error instanceof Error ? error.message : String(error)}\n${usage ? `${USAGE}\n` : ''}`);
  process.exitCode = usage ? 2 : 1;
});
