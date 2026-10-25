import { mkdtempSync, rmSync } from 'node:fs';
import { connect, type Server } from 'node:net';
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
const dirs: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((s) => new Promise((resolve) => s.close(resolve))));
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

async function start(guardian: Guardian = createFakeGuardian({ policy })) {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-'));
  dirs.push(dir);
  const path = join(dir, 'g.sock');
  servers.push(await serveGuardianSocket(guardian, policy.agentId, path));
  return path;
}

/** Send raw text, collect complete response lines until the server closes or `want` lines arrive. */
function exchange(path: string, text: string, want: number): Promise<{ lines: unknown[]; closed: boolean }> {
  return new Promise((resolve) => {
    const sock = connect(path);
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
