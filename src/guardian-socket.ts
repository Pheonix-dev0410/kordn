import { createServer, type Server, type Socket } from 'node:net';
import type { z } from 'zod';
import type { CallResult, Guardian } from './guardian-api.js';
import { MAX_FRAME_BYTES, type SocketResponse, SocketRequest } from './schema.js';

// Contain mode: the guardian side of the Unix socket. Newline-delimited JSON frames.
// The agent's identity is the socket it connected to (bound by the launcher), never
// anything in the payload. A malformed or oversized frame closes the connection.

export function serveGuardianSocket(guardian: Guardian, agentId: string, socketPath: string): Promise<Server> {
  const server = createServer((socket) => handleConnection(guardian, agentId, socket));
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}

function handleConnection(guardian: Guardian, agentId: string, socket: Socket): void {
  let buffered = '';
  // Responses go out in request order even though handleCall is async.
  let queue = Promise.resolve();

  socket.setEncoding('utf8');
  socket.on('data', (chunk: string) => {
    buffered += chunk;
    let newline: number;
    while ((newline = buffered.indexOf('\n')) !== -1) {
      const line = buffered.slice(0, newline);
      buffered = buffered.slice(newline + 1);
      if (Buffer.byteLength(line, 'utf8') > MAX_FRAME_BYTES) return socket.destroy();
      const request = parseFrame(line);
      if (!request) return socket.destroy();
      queue = queue.then(async () => {
        // A throwing guardian must fail closed for this call without wedging the queue
        // or crashing the process on an unhandled rejection.
        let result: CallResult;
        try {
          result = await guardian.handleCall(agentId, request.tool, request.args);
        } catch {
          result = { ok: false, error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' } };
        }
        const response: SocketResponse = result.ok
          ? { v: 1, id: request.id, ok: true, result: result.result }
          : { v: 1, id: request.id, ok: false, error: result.error };
        if (!socket.destroyed) socket.write(`${JSON.stringify(response)}\n`);
      });
    }
    if (Buffer.byteLength(buffered, 'utf8') > MAX_FRAME_BYTES) socket.destroy();
  });
  socket.on('error', () => socket.destroy());
}

function parseFrame(line: string): z.infer<typeof SocketRequest> | null {
  try {
    const parsed = SocketRequest.safeParse(JSON.parse(line));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
