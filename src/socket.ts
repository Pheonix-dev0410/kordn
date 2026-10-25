import { createConnection, createServer } from 'node:net';
import type { Server } from 'node:net';
import { chmod, stat } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';
import { Guardian, GuardianError } from './guardian.js';
import { DenyCode, MAX_FRAME_BYTES, SocketRequest } from './schema.js';
import type { SocketResponse } from './schema.js';

/** One private socket per agent; only the trusted launcher supplies its identity. */
export async function serveGuardian(guardian: Guardian, path: string): Promise<Server> {
  const directory = await stat(dirname(path));
  if (!directory.isDirectory() || (directory.mode & 0o077) !== 0) throw new Error('guardian socket needs a private directory');
  await guardian.reconcile();
  const server = createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let frameTimer = setTimeout(() => socket.destroy(), 30_000);
    socket.on('close', () => clearTimeout(frameTimer));
    socket.on('error', () => {});
    socket.setTimeout(30_000, () => socket.destroy());
    socket.on('data', (chunk: Buffer) => {
      socket.pause();
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_FRAME_BYTES + 1) { socket.destroy(); return; }
      let completedFrame = false;
      void (async () => {
        while (buffer.includes(10) && !socket.destroyed) {
          clearTimeout(frameTimer);
          completedFrame = true;
          const end = buffer.indexOf(10);
          const frame = buffer.subarray(0, end);
          buffer = buffer.subarray(end + 1);
          let id = 'invalid';
          let response: SocketResponse;
          try {
            let request;
            try {
              const raw = JSON.parse(frame.toString('utf8'));
              if (typeof raw?.id === 'string' && raw.id.length <= 64) id = raw.id;
              request = SocketRequest.parse(raw);
            } catch {
              guardian.ledger.recordDenied(guardian.agentId, 'INVALID_ARGUMENTS');
              throw new GuardianError('INVALID_ARGUMENTS');
            }
            id = request.id;
            const result = await guardian.handleCall(guardian.agentId, request.tool, request.args);
            response = { v: 1, id, ok: true, result };
          } catch (error) {
            response = { v: 1, id, ok: false, error: {
              code: error instanceof GuardianError ? error.code : 'INTERNAL_UNAVAILABLE',
              message: error instanceof GuardianError ? error.code : 'Guardian unavailable',
            } };
          }
          if (!socket.destroyed) {
            socket.write(`${JSON.stringify(response)}\n`);
            if (socket.writableLength > MAX_FRAME_BYTES) { socket.destroy(); return; }
          }
        }
      })().catch(() => { socket.destroy(); }).finally(() => {
        if (completedFrame && !socket.destroyed) frameTimer = setTimeout(() => socket.destroy(), 30_000);
        socket.resume();
      });
    });
  });
  server.maxConnections = 64;
  // The launcher must provide a private directory; never unlink an existing socket.
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(path, () => { server.off('error', reject); resolve(); });
  });
  try { await chmod(path, 0o600); }
  catch (error) { server.close(); throw error; }
  return server;
}

/** No adapter fallback: a dead or unresponsive guardian always fails closed. */
export async function callGuardian(path: string, tool: string, args: unknown, timeoutMs = 10_000): Promise<unknown> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new GuardianError('INVALID_ARGUMENTS');
  const id = randomUUID();
  let frame: Buffer;
  try { frame = Buffer.from(`${JSON.stringify({ v: 1, id, tool, args })}\n`); }
  catch { throw new GuardianError('INVALID_ARGUMENTS'); }
  if (frame.length - 1 > MAX_FRAME_BYTES) throw new GuardianError('INVALID_ARGUMENTS');
  return new Promise((resolve, reject) => {
    const socket = createConnection(path);
    let buffer = Buffer.alloc(0);
    let settled = false;
    let timer: ReturnType<typeof setTimeout>;
    const fail = () => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        reject(new GuardianError('INTERNAL_UNAVAILABLE'));
      }
    };
    timer = setTimeout(fail, timeoutMs);
    socket.on('error', fail);
    socket.on('close', fail);
    socket.on('connect', () => socket.write(frame));
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > MAX_FRAME_BYTES + 1) { fail(); return; }
      const end = buffer.indexOf(10);
      if (end < 0) return;
      try {
        const response = JSON.parse(buffer.subarray(0, end).toString('utf8')) as SocketResponse;
        if (response?.v !== 1 || response.id !== id || typeof response.ok !== 'boolean') { fail(); return; }
        let error: GuardianError | undefined;
        if (!response.ok) {
          const code = DenyCode.safeParse(response.error?.code);
          if (!code.success) { fail(); return; }
          error = new GuardianError(code.data);
        }
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        if (error) reject(error);
        else if (response.ok) resolve(response.result);
      } catch { fail(); }
    });
  });
}
