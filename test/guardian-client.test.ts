import { mkdtempSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
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
