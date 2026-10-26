import { mkdtempSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { createGuardianClient } from '../src/guardian-client.js';
import { serveGuardianSocket } from '../src/guardian-socket.js';
import { MAX_FRAME_BYTES, Policy } from '../src/schema.js';

const policy = Policy.parse(policyJson);
const servers: Server[] = [];

afterEach(() => {
  for (const s of servers.splice(0)) s.close();
});

const socketPath = () => join(mkdtempSync(join(tmpdir(), 'kordn-')), 'g.sock');
const unavailable = { ok: false, error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' } };

async function startGuardian() {
  const path = socketPath();
  const guardian = createFakeGuardian({ policy });
  servers.push(await serveGuardianSocket(guardian, policy.agentId, path));
  return { path, guardian };
}

/** A socket server that hands each connection to `onConnection` instead of a guardian. */
async function startRaw(onConnection: (socket: Socket) => void) {
  const path = socketPath();
  const server = createServer(onConnection);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(path, resolve));
  return path;
}

describe('guardian socket client', () => {
  it('round-trips a call through the guardian socket', async () => {
    const { path } = await startGuardian();
    const handleCall = createGuardianClient(path);
    expect(await handleCall('ignored', 'af_get_balance', { resourceId: policy.resourceId })).toMatchObject({
      ok: true,
      result: { currency: 'USD', balanceMinor: expect.any(Number) },
    });
  });

  it('relays denials and the guardian logs unknown tools', async () => {
    const { path, guardian } = await startGuardian();
    const handleCall = createGuardianClient(path);
    expect(await handleCall('ignored', 'shell', { cmd: 'id' })).toMatchObject({
      ok: false,
      error: { code: 'UNKNOWN_ACTION' },
    });
    expect(await guardian.listActivity({ events: ['policy.denied'] })).toMatchObject([
      { agent: policy.agentId, reasonCode: 'UNKNOWN_ACTION' },
    ]);
  });

  it('forwards args unparsed and sends no identity', async () => {
    const frames: unknown[] = [];
    const path = await startRaw((socket) => {
      socket.setEncoding('utf8');
      socket.once('data', (line: string) => {
        const frame = JSON.parse(line) as { id: string };
        frames.push(frame);
        socket.end(`${JSON.stringify({ v: 1, id: frame.id, ok: true, result: { fine: true } })}\n`);
      });
    });
    const args = { resourceId: 'x', policyApproved: true, nested: { agentId: 'root' } };
    expect(await createGuardianClient(path)('sandbox-demo-01', 'af_get_balance', args)).toEqual({
      ok: true,
      result: { fine: true },
    });
    expect(frames).toEqual([{ v: 1, id: expect.any(String), tool: 'af_get_balance', args }]);
  });

  it('returns INTERNAL_UNAVAILABLE when nothing is listening', async () => {
    const handleCall = createGuardianClient(join(mkdtempSync(join(tmpdir(), 'kordn-')), 'missing.sock'));
    expect(await handleCall('a', 'af_get_balance', { resourceId: policy.resourceId })).toEqual(unavailable);
  });

  it('answers a second call while the first is stuck on a hung guardian connection', async () => {
    let hung: Socket | undefined;
    const path = await startRaw((socket) => {
      if (!hung) return void (hung = socket); // the first connection never gets a reply
      socket.setEncoding('utf8');
      socket.once('data', (line: string) => {
        const { id } = JSON.parse(line) as { id: string };
        socket.end(`${JSON.stringify({ v: 1, id, ok: true, result: { second: true } })}\n`);
      });
    });
    const handleCall = createGuardianClient(path, { timeoutMs: 5000 });
    let firstSettled = false;
    const first = handleCall('a', 'af_get_balance', {}).finally(() => (firstSettled = true));
    while (!hung) await new Promise((resolve) => setTimeout(resolve, 5));
    expect(await handleCall('a', 'af_get_balance', {})).toEqual({ ok: true, result: { second: true } });
    expect(firstSettled).toBe(false);
    hung.destroy();
    expect(await first).toEqual(unavailable);
  });

  it('times out a guardian that never answers', async () => {
    const path = await startRaw(() => {});
    const started = Date.now();
    expect(await createGuardianClient(path, { timeoutMs: 100 })('a', 'af_get_balance', {})).toEqual(unavailable);
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it.each([
    ['garbage', 'not json\n'],
    ['a reply to another request', `${JSON.stringify({ v: 1, id: 'other', ok: true, result: {} })}\n`],
    ['an unknown deny code', `${JSON.stringify({ v: 1, id: '?', ok: false, error: { code: 'ALLOW', message: '' } })}\n`],
    ['a closed connection', ''],
  ])('treats %s as unavailable', async (_name, reply) => {
    const path = await startRaw((socket) => {
      socket.setEncoding('utf8');
      socket.once('data', (line: string) => {
        const { id } = JSON.parse(line) as { id: string };
        socket.end(reply.replace('"?"', JSON.stringify(id)));
      });
    });
    expect(await createGuardianClient(path, { timeoutMs: 1000 })('a', 'af_get_balance', {})).toEqual(unavailable);
  });

  it('still reaches the guardian when the call has no args, so the attempt is logged', async () => {
    const { path, guardian } = await startGuardian();
    expect(await createGuardianClient(path)('a', 'shell', undefined)).toMatchObject({
      ok: false,
      error: { code: 'UNKNOWN_ACTION' },
    });
    expect(await guardian.listActivity({ events: ['policy.denied'] })).toMatchObject([{ reasonCode: 'UNKNOWN_ACTION' }]);
  });

  it('still reaches the guardian with oversized args or tool names, so the attempt is logged', async () => {
    const { path, guardian } = await startGuardian();
    const handleCall = createGuardianClient(path);
    const big = { resourceId: policy.resourceId, pad: 'x'.repeat(MAX_FRAME_BYTES) };
    expect(await handleCall('a', 'af_get_balance', big)).toMatchObject({ ok: false, error: { code: 'INVALID_ARGUMENTS' } });
    expect(await handleCall('a', 'x'.repeat(500), {})).toMatchObject({ ok: false, error: { code: 'UNKNOWN_ACTION' } });
    expect(await guardian.listActivity({ events: ['policy.denied'] })).toHaveLength(2);
  });
});

describe('guardian socket client concurrency', () => {
  it('rejects a maxConcurrent that is not a positive integer', () => {
    for (const maxConcurrent of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => createGuardianClient('/tmp/x.sock', { maxConcurrent })).toThrow(RangeError);
    }
  });

  it('rejects a timeoutMs that is not a positive integer a timer can hold', () => {
    for (const timeoutMs of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 31]) {
      expect(() => createGuardianClient('/tmp/x.sock', { timeoutMs })).toThrow(RangeError);
    }
    expect(() => createGuardianClient('/tmp/x.sock', { timeoutMs: 2 ** 31 - 1 })).not.toThrow();
  });

  it('fails a call whose args cannot be encoded without leaking its slot', async () => {
    const { path, guardian } = await startGuardian();
    const handleCall = createGuardianClient(path, { maxConcurrent: 1 });
    expect(await handleCall('a', 'af_get_balance', { resourceId: policy.resourceId, n: 1n })).toEqual(unavailable);
    // With one slot, a leaked slot would leave this call queued until it timed out.
    expect(await handleCall('a', 'af_get_balance', { resourceId: policy.resourceId })).toMatchObject({ ok: true });
    expect(await guardian.listActivity({ events: ['read.executed'] })).toHaveLength(1);
  });

  it('answers and logs 40 concurrent calls, staying under the socket connection cap', async () => {
    const path = socketPath();
    const guardian = createFakeGuardian({ policy });
    let inFlight = 0;
    let peak = 0;
    const slow = {
      ...guardian,
      handleCall: async (agent: string, tool: unknown, args: unknown) => {
        peak = Math.max(peak, ++inFlight);
        await new Promise((resolve) => setTimeout(resolve, 50));
        inFlight -= 1;
        return guardian.handleCall(agent, tool, args);
      },
    };
    servers.push(await serveGuardianSocket(slow, policy.agentId, path));
    const handleCall = createGuardianClient(path);
    const results = await Promise.all(
      Array.from({ length: 40 }, () => handleCall('a', 'af_get_balance', { resourceId: policy.resourceId })),
    );
    expect(results.filter((r) => r.ok)).toHaveLength(40);
    expect(await guardian.listActivity({ events: ['read.executed'], limit: 100 })).toHaveLength(40);
    expect(peak).toBeLessThanOrEqual(16);
  });

  it('dispatches queued calls in arrival order', async () => {
    const seen: string[] = [];
    const path = await startRaw((socket) => {
      socket.setEncoding('utf8');
      socket.once('data', (line: string) => {
        const { id, tool } = JSON.parse(line) as { id: string; tool: string };
        seen.push(tool);
        // Answer later than the next call queues up, so order is decided by the queue.
        setTimeout(() => socket.end(`${JSON.stringify({ v: 1, id, ok: true, result: {} })}\n`), 5);
      });
    });
    const handleCall = createGuardianClient(path, { maxConcurrent: 1 });
    const tools = ['t0', 't1', 't2', 't3', 't4', 't5'];
    await Promise.all(tools.map((tool) => handleCall('a', tool, {})));
    expect(seen).toEqual(tools);
  });

  it('fails queued calls closed when the guardian hangs, without leaking sockets', async () => {
    const open = new Set<Socket>();
    let peak = 0;
    let total = 0;
    const path = await startRaw((socket) => {
      total += 1;
      open.add(socket);
      peak = Math.max(peak, open.size);
      socket.on('close', () => open.delete(socket));
      socket.resume(); // read (and ignore) the frame, so the client's hang-up is seen
    });
    // Fake only the call timers, so all six expire at the same instant. With real timers a
    // queued call created a millisecond later can be dispatched just before it expires.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    let results: unknown[];
    try {
      const handleCall = createGuardianClient(path, { timeoutMs: 200, maxConcurrent: 2 });
      const pending = Promise.all(Array.from({ length: 6 }, () => handleCall('a', 'af_get_balance', {})));
      while (total < 2) await new Promise((resolve) => setImmediate(resolve));
      // One timeout's worth of time settles every call: queued time counts against the timeout.
      vi.advanceTimersByTime(200);
      results = await pending;
    } finally {
      vi.useRealTimers();
    }
    expect(results).toEqual(Array.from({ length: 6 }, () => unavailable));
    expect(peak).toBeLessThanOrEqual(2);
    // Only the two dispatched calls ever connected: the four that timed out in the queue never did.
    expect(total).toBe(2);
    for (let i = 0; i < 50 && open.size > 0; i++) await new Promise((resolve) => setTimeout(resolve, 10));
    expect(open.size).toBe(0);
  });
});
