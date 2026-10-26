import { createConnection } from 'node:net';
import { randomUUID } from 'node:crypto';
import { GuardianError } from '../src/ledger.js';
import { DenyCode, MAX_FRAME_BYTES } from '../src/schema.js';
import type { SocketResponse } from '../src/schema.js';

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
