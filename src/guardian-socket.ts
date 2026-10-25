import { createServer, type Server, type Socket } from 'node:net';
import type { z } from 'zod';
import type { CallResult, Guardian } from './guardian-api.js';
import { MAX_FRAME_BYTES, type SocketResponse, SocketRequest } from './schema.js';

// Contain mode: the guardian side of the Unix socket. Newline-delimited JSON frames.
// The agent's identity is the socket it connected to, never anything in the payload. The
// launcher binds the path and owns its permissions (and stale socket files): anyone who can
// connect to it speaks as `agentId`. A malformed or oversized frame closes the connection.
// The agent is untrusted, so every per-connection resource is bounded: buffered bytes, queued
// calls, unread responses, idle time and the number of connections.

export interface GuardianSocketOptions {
  /** Concurrent connections. Further ones are closed on arrival. */
  maxConnections?: number;
  /** Requests queued on one connection before it stops reading until they drain. */
  maxInFlight?: number;
  /** A connection with no traffic either way for this long is closed. */
  idleTimeoutMs?: number;
}

const DEFAULTS: Required<GuardianSocketOptions> = {
  maxConnections: 8,
  maxInFlight: 32,
  idleTimeoutMs: 10 * 60_000,
};

const INTERNAL_UNAVAILABLE: CallResult = {
  ok: false,
  error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' },
};

export function serveGuardianSocket(
  guardian: Guardian,
  agentId: string,
  socketPath: string,
  options: GuardianSocketOptions = {},
): Promise<Server> {
  const limits = { ...DEFAULTS, ...options };
  const server = createServer((socket) => handleConnection(guardian, agentId, socket, limits));
  server.maxConnections = limits.maxConnections;
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}

function handleConnection(guardian: Guardian, agentId: string, socket: Socket, limits: Required<GuardianSocketOptions>): void {
  // Bytes of the current, not yet newline-terminated frame. Kept raw so each byte is scanned
  // once (no rescans on drip-fed input) and a UTF-8 character split across chunks is decoded
  // only once the whole line is in. 0x0a never occurs inside a multibyte character.
  let partial: Buffer | undefined;
  let partialBytes = 0;
  // Responses go out in request order even though handleCall is async.
  let queue = Promise.resolve();
  let inFlight = 0;

  socket.setTimeout(limits.idleTimeoutMs, () => socket.destroy());

  socket.on('data', (chunk: Buffer) => {
    let start = 0;
    let newline: number;
    while ((newline = chunk.indexOf(0x0a, start)) !== -1) {
      const piece = chunk.subarray(start, newline);
      start = newline + 1;
      if (partialBytes + piece.length > MAX_FRAME_BYTES) return socket.destroy();
      let line: string;
      if (partial && partialBytes > 0) {
        piece.copy(partial, partialBytes);
        line = partial.toString('utf8', 0, partialBytes + piece.length);
        partialBytes = 0;
      } else {
        line = piece.toString('utf8');
      }
      const request = parseFrame(line);
      if (!request) return socket.destroy();
      enqueue(request);
    }
    const rest = chunk.subarray(start);
    if (rest.length === 0) return;
    if (partialBytes + rest.length > MAX_FRAME_BYTES) return socket.destroy();
    partial ??= Buffer.allocUnsafe(MAX_FRAME_BYTES);
    rest.copy(partial, partialBytes);
    partialBytes += rest.length;
  });
  socket.on('error', () => socket.destroy());

  function enqueue(request: z.infer<typeof SocketRequest>): void {
    inFlight += 1;
    // Frames already read in this chunk still queue past the cap; nothing more is read.
    if (inFlight >= limits.maxInFlight) socket.pause();
    queue = queue.then(async () => {
      // A request queued before the connection died (e.g. ahead of a bad frame in the same
      // chunk) must not run: nobody would see its result.
      if (!socket.destroyed) await answer(request);
      inFlight -= 1;
      if (inFlight < limits.maxInFlight && !socket.destroyed) socket.resume();
    });
  }

  async function answer(request: z.infer<typeof SocketRequest>): Promise<void> {
    // A throwing guardian (or a result with no JSON form) must fail closed for this call
    // without wedging the queue or crashing the process on an unhandled rejection.
    let line: string;
    try {
      line = encode(request.id, await guardian.handleCall(agentId, request.tool, request.args));
    } catch {
      line = encode(request.id, INTERNAL_UNAVAILABLE);
    }
    if (socket.destroyed) return;
    // A client that doesn't read its responses stalls its own queue, rather than growing ours.
    if (!socket.write(line)) await drained(socket);
  }
}

function encode(id: string, result: CallResult): string {
  const response: SocketResponse = result.ok
    ? { v: 1, id, ok: true, result: result.result }
    : { v: 1, id, ok: false, error: result.error };
  return `${JSON.stringify(response)}\n`;
}

function drained(socket: Socket): Promise<void> {
  return new Promise((resolve) => {
    if (socket.destroyed) return resolve();
    const done = () => {
      socket.off('drain', done);
      socket.off('close', done);
      resolve();
    };
    socket.on('drain', done);
    socket.on('close', done);
  });
}

function parseFrame(line: string): z.infer<typeof SocketRequest> | null {
  try {
    const parsed = SocketRequest.safeParse(JSON.parse(line));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}
