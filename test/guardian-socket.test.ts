import { mkdtempSync, rmSync } from 'node:fs';
import { connect, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import type { Guardian } from '../src/guardian-api.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { MAX_FRAME_BYTES, Policy } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const servers: Server[] = [];
const sockets: Socket[] = [];
const dirs: string[] = [];

afterEach(async () => {
  // close() waits for open connections, so a failed test mustn't leave one behind.
  for (const s of sockets.splice(0)) s.destroy();
  await Promise.all(servers.splice(0).map((s) => new Promise((resolve) => s.close(resolve))));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

async function startWith(guardian: Guardian, options?: Parameters<typeof serveGuardianSocket>[3]) {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-'));
  dirs.push(dir);
  const path = join(dir, 'g.sock');
  const server = await serveGuardianSocket(guardian, policy.agentId, path, options);
  servers.push(server);
  const connections: Socket[] = [];
  server.on('connection', (s) => {
    connections.push(s);
    sockets.push(s);
  });
  return { path, connections };
}

async function start(guardian: Guardian = createFakeGuardian({ policy })) {
  return (await startWith(guardian)).path;
}

function client(path: string): Socket {
  const sock = connect(path);
  // The server may drop us mid-write (that is what several tests check): close, not crash.
  sock.on('error', () => sock.destroy());
  sockets.push(sock);
  return sock;
}

/** Send raw text, collect complete response lines until the server closes or `want` lines arrive. */
function exchange(path: string, text: string, want: number): Promise<{ lines: unknown[]; closed: boolean }> {
  return new Promise((resolve) => {
    const sock = client(path);
    let buf = '';
    // Only lines the server finished with a newline: a trailing partial line is not a response.
    const complete = () => buf.split('\n').slice(0, -1);
    const done = (closed: boolean) => {
      sock.destroy();
      resolve({ lines: complete().map((l) => JSON.parse(l)), closed });
    };
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => {
      buf += d;
      if (complete().length >= want) done(false);
    });
    sock.on('close', () => done(true));
    sock.write(text);
  });
}

const frame = (id: string, tool: string, args: unknown) => `${JSON.stringify({ v: 1, id, tool, args })}\n`;

describe('guardian socket', () => {
  it('answers requests in order with the agent bound to the socket', async () => {
    const path = await start();
    const { lines } = await exchange(
      path,
      frame('1', 'af_get_balance', { resourceId: policy.resourceId }) + frame('2', 'shell', { cmd: 'id' }),
      2,
    );
    expect(lines).toMatchObject([
      { v: 1, id: '1', ok: true, result: { currency: 'USD' } },
      { v: 1, id: '2', ok: false, error: { code: 'UNKNOWN_ACTION' } },
    ]);
  });

  it('closes the connection on a malformed frame', async () => {
    const path = await start();
    expect(await exchange(path, '{"v":1,"id":"1","tool":"x","args":{},"agentId":"root"}\n', 1)).toEqual({
      lines: [],
      closed: true,
    });
    expect((await exchange(path, 'not json\n', 1)).closed).toBe(true);
  });

  it('closes the connection on an oversized frame', async () => {
    const path = await start();
    expect((await exchange(path, 'x'.repeat(MAX_FRAME_BYTES + 1), 1)).closed).toBe(true);
  });

  it('answers INTERNAL_UNAVAILABLE when the guardian throws, and keeps serving', async () => {
    const guardian = createFakeGuardian({ policy });
    let calls = 0;
    const flaky = {
      ...guardian,
      handleCall: (agent: string, tool: unknown, args: unknown) => {
        calls += 1;
        return calls === 1 ? Promise.reject(new Error('db locked')) : guardian.handleCall(agent, tool, args);
      },
    };
    const path = await start(flaky);
    const { lines } = await exchange(
      path,
      frame('1', 'af_get_balance', { resourceId: policy.resourceId }) + frame('2', 'af_get_balance', { resourceId: policy.resourceId }),
      2,
    );
    expect(lines).toMatchObject([
      { v: 1, id: '1', ok: false, error: { code: 'INTERNAL_UNAVAILABLE' } },
      { v: 1, id: '2', ok: true, result: { currency: 'USD' } },
    ]);
  });
});

const balance = (id: string) => frame(id, 'af_get_balance', { resourceId: policy.resourceId });
const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));

/** A guardian that records calls and answers whatever `answer` says, when it says. */
function stubGuardian(answer: () => Promise<unknown> = async () => ({ ok: true })) {
  const calls: unknown[] = [];
  const guardian: Guardian = {
    ...createFakeGuardian({ policy }),
    handleCall: async (_agent, tool) => {
      calls.push(tool);
      return { ok: true, result: await answer() };
    },
  };
  return { guardian, calls };
}

/** Write each piece separately, letting the server read in between. */
async function writeInPieces(path: string, pieces: (string | Buffer)[], want: number) {
  const sock = client(path);
  const lines: { id: string }[] = [];
  let buf = '';
  const closed = new Promise<void>((resolve) => sock.on('close', () => resolve()));
  sock.setEncoding('utf8');
  sock.on('data', (d: string) => {
    buf += d;
    const parts = buf.split('\n');
    buf = parts.pop()!;
    for (const p of parts) lines.push(JSON.parse(p));
    if (lines.length >= want) sock.destroy();
  });
  for (const piece of pieces) {
    sock.write(piece);
    await tick(1);
  }
  await closed;
  return lines;
}

describe('guardian socket framing', () => {
  it('answers a frame split across writes', async () => {
    const path = await start();
    const text = balance('split');
    expect(await writeInPieces(path, [text.slice(0, 10), text.slice(10)], 1)).toMatchObject([{ id: 'split', ok: true }]);
  });

  it('reassembles a UTF-8 character split across writes', async () => {
    const path = await start();
    const bytes = Buffer.from(balance('€uro'), 'utf8');
    const cut = bytes.indexOf(Buffer.from('€', 'utf8')) + 1;
    expect(await writeInPieces(path, [bytes.subarray(0, cut), bytes.subarray(cut)], 1)).toMatchObject([{ id: '€uro', ok: true }]);
  });

  it('answers a frame drip-fed a byte at a time', async () => {
    const path = await start();
    expect(await writeInPieces(path, [...balance('drip')], 1)).toMatchObject([{ id: 'drip', ok: true }]);
  });
});

describe('guardian socket limits', () => {
  it('never calls the guardian for a request queued before a bad frame', async () => {
    const { guardian, calls } = stubGuardian();
    const path = await start(guardian);
    expect(await exchange(path, `${balance('1')}${balance('2')}not json\n`, 1)).toEqual({ lines: [], closed: true });
    await tick(20);
    expect(calls).toEqual([]);
  });

  it('stops reading while calls back up, and catches up once they drain', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const { guardian, calls } = stubGuardian(async () => {
      await gate;
      return {};
    });
    const { path, connections } = await startWith(guardian, { maxInFlight: 4 });
    const count = 2000;
    const pad = 'x'.repeat(500);
    const text = Array.from({ length: count }, (_, i) => frame(String(i), 'af_get_balance', { pad })).join('');
    const done = exchange(path, text, count);
    await tick(100);
    expect(calls).toHaveLength(1);
    expect(connections[0]!.bytesRead).toBeLessThan(Buffer.byteLength(text) / 4);
    release();
    const { lines } = await done;
    expect(lines.map((l) => (l as { id: string }).id)).toEqual(Array.from({ length: count }, (_, i) => String(i)));
  });

  it('stays bounded against a client that never reads its responses', async () => {
    const big = 'y'.repeat(8 * 1024);
    const { guardian, calls } = stubGuardian(async () => ({ big }));
    const path = await start(guardian);
    const count = 3000;
    const sock = client(path);
    sock.pause();
    sock.write(Array.from({ length: count }, (_, i) => balance(String(i))).join(''));
    await tick(200);
    const settled = calls.length;
    await tick(100);
    sock.destroy();
    expect(calls.length).toBe(settled);
    expect(settled).toBeLessThan(count / 10);
  });

  it('closes an idle connection', async () => {
    const { path } = await startWith(createFakeGuardian({ policy }), { idleTimeoutMs: 50 });
    expect(await exchange(path, '', 1)).toEqual({ lines: [], closed: true });
  });

  it('refuses connections beyond maxConnections', async () => {
    const { path } = await startWith(createFakeGuardian({ policy }), { maxConnections: 1 });
    const first = client(path);
    await new Promise((resolve) => first.on('connect', resolve));
    await tick(10);
    expect(await exchange(path, balance('2'), 1)).toEqual({ lines: [], closed: true });
    first.destroy();
    await tick(10);
    expect((await exchange(path, balance('3'), 1)).lines).toMatchObject([{ id: '3', ok: true }]);
  });
});

describe('guardian socket failures', () => {
  it('answers INTERNAL_UNAVAILABLE for a result it cannot serialize, and keeps serving', async () => {
    let n = 0;
    const { guardian } = stubGuardian(async () => (++n === 1 ? { amount: 1n } : {}));
    const path = await start(guardian);
    const { lines } = await exchange(path, balance('1') + balance('2'), 2);
    expect(lines).toMatchObject([
      { id: '1', ok: false, error: { code: 'INTERNAL_UNAVAILABLE' } },
      { id: '2', ok: true },
    ]);
  });
});
