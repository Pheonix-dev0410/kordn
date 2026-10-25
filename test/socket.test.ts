import { createConnection, createServer } from 'node:net';
import type { Server } from 'node:net';
import { once } from 'node:events';
import { chmodSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { callGuardian, serveGuardian } from '../src/socket.js';
import { MAX_FRAME_BYTES } from '../src/schema.js';
import { harness } from './helpers.js';

let h: ReturnType<typeof harness>;
let server: Server | undefined;
afterEach(async () => {
  vi.useRealTimers();
  if (server?.listening) await new Promise<void>((resolve) => server!.close(() => resolve()));
  server = undefined;
  h?.close();
});

async function raw(path: string, fragments: string[], count = 1) {
  return new Promise<unknown[]>((resolve, reject) => {
    const socket = createConnection(path);
    let buffer = '';
    const replies: unknown[] = [];
    socket.setEncoding('utf8');
    socket.setTimeout(1000, () => { socket.destroy(); reject(new Error('socket test timed out')); });
    socket.on('error', reject);
    socket.on('connect', () => { for (const fragment of fragments) socket.write(fragment); });
    socket.on('data', (data) => {
      buffer += data;
      while (buffer.includes('\n')) {
        const end = buffer.indexOf('\n');
        replies.push(JSON.parse(buffer.slice(0, end)));
        buffer = buffer.slice(end + 1);
        if (replies.length === count) { socket.destroy(); resolve(replies); }
      }
    });
  });
}

describe('guardian Unix socket', () => {
  it('handles fragmented and pipelined frames with server-bound identity', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    server = await serveGuardian(h.guardian, path);
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const a = JSON.stringify({ v: 1, id: 'a', tool: 'af_get_balance', args: { resourceId: h.policy.resourceId } });
    const b = JSON.stringify({ v: 1, id: 'b', tool: 'shell', args: {} });
    const responses = await raw(path, [a.slice(0, 10), `${a.slice(10)}\n${b}\n`], 2);
    expect(responses[0]).toMatchObject({ v: 1, id: 'a', ok: true });
    expect(responses[1]).toMatchObject({ id: 'b', ok: false, error: { code: 'UNKNOWN_ACTION' } });
    const [spoof] = await raw(path, [JSON.stringify({ v: 1, id: 'spoof', tool: 'af_get_balance', args: {}, agentId: 'other' }) + '\n']);
    expect(spoof).toMatchObject({ id: 'spoof', ok: false, error: { code: 'INVALID_ARGUMENTS' } });
    expect(h.guardian.listActivity({ event: 'policy.denied' })).toHaveLength(2);
  });

  it('rejects malformed JSON and disconnects oversized frames', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    server = await serveGuardian(h.guardian, path);
    const [response] = await raw(path, ['{broken}\n']);
    expect(response).toMatchObject({ ok: false, error: { code: 'INVALID_ARGUMENTS' } });
    const socket = createConnection(path);
    socket.on('error', () => {});
    const closed = once(socket, 'close');
    await once(socket, 'connect');
    socket.write('x'.repeat(MAX_FRAME_BYTES + 2));
    await closed;
  });

  it('refuses a public directory and does not replace an existing socket', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    chmodSync(h.dir, 0o755);
    await expect(serveGuardian(h.guardian, path)).rejects.toThrow('private directory');
    chmodSync(h.dir, 0o700);
    server = await serveGuardian(h.guardian, path);
    await expect(serveGuardian(h.guardian, path)).rejects.toMatchObject({ code: 'EADDRINUSE' });
  });

  it('fails closed on a missing guardian, invalid replies, and response timeouts', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    await expect(callGuardian(path, 'af_get_balance', {})).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    server = createServer((socket) => {
      socket.on('error', () => {});
      socket.on('data', (data) => {
        const request = JSON.parse(data.toString());
        socket.end(JSON.stringify({ v: 1, id: request.id, ok: false }) + '\n');
      });
    });
    server.listen(path);
    await once(server, 'listening');
    await expect(callGuardian(path, 'af_get_balance', {})).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    await new Promise<void>((resolve) => server!.close(() => resolve()));
    server = createServer((socket) => { socket.on('data', () => {}); });
    server.listen(path);
    await once(server, 'listening');
    await expect(callGuardian(path, 'af_get_balance', {}, 20)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
  });

  it('enforces the call deadline even when the peer keeps trickling response bytes', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    server = createServer((socket) => {
      socket.on('error', () => {});
      const interval = setInterval(() => socket.write(' '), 5);
      const stop = setTimeout(() => socket.destroy(), 300);
      socket.on('close', () => { clearInterval(interval); clearTimeout(stop); });
    });
    server.listen(path);
    await once(server, 'listening');
    const started = performance.now();
    await expect(callGuardian(path, 'af_get_balance', {}, 20)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect(performance.now() - started).toBeLessThan(200);
  });

  it('bounds simultaneous connections instead of accepting unbounded idle peers', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    server = await serveGuardian(h.guardian, path);
    const dropped = once(server, 'drop');
    const sockets = Array.from({ length: 65 }, () => {
      const socket = createConnection(path);
      socket.on('error', () => {});
      return socket;
    });
    try {
      await Promise.all(sockets.map((socket) => new Promise<void>((resolve) => {
        socket.once('connect', resolve);
        socket.once('error', () => resolve());
      })));
      await dropped;
      const count = await new Promise<number>((resolve, reject) => server!.getConnections((error, n) => error ? reject(error) : resolve(n)));
      expect(count).toBe(64);
    } finally { for (const socket of sockets) socket.destroy(); }
  });

  it('disconnects an incomplete frame even if bytes arrive before each idle timeout', async () => {
    h = harness();
    const path = join(h.dir, 'guardian.sock');
    server = await serveGuardian(h.guardian, path);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const accepted = once(server, 'connection');
    const socket = createConnection(path);
    socket.on('error', () => {});
    const closed = once(socket, 'close');
    try {
      await once(socket, 'connect');
      await accepted;
      socket.write(' ');
      await new Promise(setImmediate);
      await vi.advanceTimersByTimeAsync(15_000);
      socket.write(' ');
      await new Promise(setImmediate);
      await vi.advanceTimersByTimeAsync(15_001);
      await closed;
    } finally { socket.destroy(); }
  });
});
