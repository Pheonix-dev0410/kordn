// Minimal scripted agent for the Contain sandbox (v0.1 has no live model). It is the MCP
// client: it starts `kordn --guardian /run/kordn.sock` over stdio, lists the tools and
// makes one read call. Replace it through the image CMD (e.g. the hostile agent, #13).
//
// Usage: agent.mjs [--resource <resourceId>] [-- <server command...>]
// Prints one JSON line per step. Exits 0 only if the tools were listed and the read succeeded.

import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

const TIMEOUT_MS = 30_000;

const argv = process.argv.slice(2);
const split = argv.indexOf('--');
const own = split === -1 ? argv : argv.slice(0, split);
const server = split === -1 ? [process.execPath, '/app/dist/index.js', '--guardian', '/run/kordn.sock'] : argv.slice(split + 1);
const resourceFlag = own.indexOf('--resource');
const resourceId = resourceFlag === -1 ? 'mock-bank:checking-01' : own[resourceFlag + 1];

const fail = (message) => {
  process.stderr.write(`agent: ${message}\n`);
  process.exit(1);
};
setTimeout(() => fail('timed out'), TIMEOUT_MS).unref();

const child = spawn(server[0], server.slice(1), { stdio: ['pipe', 'pipe', 'inherit'] });
child.on('error', (e) => fail(`could not start the MCP server: ${e.message}`));
child.on('exit', (code) => fail(`MCP server exited (${code})`));

const waiting = new Map();
let nextId = 1;
createInterface({ input: child.stdout }).on('line', (line) => {
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return; // not JSON: ignore it, the request timeout still applies
  }
  // Only a response settles a request: it has result or error and no method. A server
  // request can carry an id that collides with ours.
  if (msg === null || typeof msg !== 'object' || 'method' in msg || !('result' in msg || 'error' in msg)) return;
  const resolve = waiting.get(msg.id);
  if (!resolve) return;
  waiting.delete(msg.id);
  resolve(msg);
});

const write = (msg) => child.stdin.write(`${JSON.stringify({ jsonrpc: '2.0', ...msg })}\n`);
const request = (method, params) =>
  new Promise((resolve) => {
    const id = nextId++;
    waiting.set(id, resolve);
    write({ id, method, params });
  });

// Older protocol versions need initialize; a stateless server answers it with an error.
// Verified against kordn's server (#9, @modelcontextprotocol/server 2.3.1, whose latest protocol is
// 2025-11-25): it negotiates through initialize and needs no per-request _meta. A later SDK on
// the stateless 2026 protocol may; the Docker end-to-end test will show it.
const init = await request('initialize', {
  protocolVersion: '2025-11-25',
  capabilities: {},
  clientInfo: { name: 'kordn-sandbox-agent', version: '0.1.0' },
});
if (init.result) write({ method: 'notifications/initialized' });

const listed = await request('tools/list', {});
const tools = listed.result?.tools?.map((t) => t.name) ?? [];
console.log(JSON.stringify({ step: 'tools/list', tools }));
if (tools.length === 0) fail(`tools/list failed: ${JSON.stringify(listed.error ?? listed.result)}`);

const called = await request('tools/call', { name: 'af_get_balance', arguments: { resourceId } });
const isError = !called.result || called.result.isError === true;
console.log(
  JSON.stringify({
    step: 'tools/call',
    tool: 'af_get_balance',
    isError,
    result: called.result?.structuredContent ?? called.result?.content ?? called.error ?? null,
  }),
);

child.removeAllListeners('exit');
child.kill();
process.exit(isError ? 1 : 0);
