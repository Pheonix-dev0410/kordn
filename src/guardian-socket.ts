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
  /** Requests queued on one connection. At the cap it stops parsing and reading until one finishes. */
  maxInFlight?: number;
  /** A connection with no traffic either way for this long is closed. */
  idleTimeoutMs?: number;
}

const DEFAULTS: Required<GuardianSocketOptions> = {
  maxConnections: 32,
  maxInFlight: 32,
  idleTimeoutMs: 10 * 60_000,
};

// Node clamps a longer timer to 1 ms, which would close every connection at once.
const MAX_TIMER_MS = 2 ** 31 - 1;

const REFUSAL_REPORT_INTERVAL_MS = 1000;

const INTERNAL_UNAVAILABLE: CallResult = {
  ok: false,
  error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' },
};

/** Throws RangeError for a limit that isn't a positive integer: 0 or NaN would wedge or unbound a connection. */
export function serveGuardianSocket(
  guardian: Guardian,
  agentId: string,
  socketPath: string,
  options: GuardianSocketOptions = {},
): Promise<Server> {
  const limits = { ...DEFAULTS, ...options };
  for (const [name, value] of Object.entries(limits)) {
    const max = name === 'idleTimeoutMs' ? MAX_TIMER_MS : Number.MAX_SAFE_INTEGER;
    if (!Number.isInteger(value) || value < 1 || value > max) throw new RangeError(`invalid ${name}: ${value}`);
  }
  const server = createServer((socket) => handleConnection(guardian, agentId, socket, limits));
  server.maxConnections = limits.maxConnections;
  reportRefusals(server, guardian);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      server.off('error', reject);
      resolve(server);
    });
  });
}

/**
 * Node closes connections beyond maxConnections itself and emits 'drop'. Each refusal reaches
 * the guardian's audit log, but at most once a second, so a connect flood can't flood the log:
 * the first refusal is reported at once, the rest of the window as one count when it ends.
 */
function reportRefusals(server: Server, guardian: Guardian): void {
  let refused = 0;
  let windowTimer: NodeJS.Timeout | undefined;
  const report = () => {
    if (refused === 0) return false;
    const count = refused;
    refused = 0;
    // The guardian promises not to reject; a broken one still mustn't take the server down.
    Promise.resolve()
      .then(() => guardian.recordRefusedConnection(count))
      .catch(() => {});
    return true;
  };
  const flush = () => {
    windowTimer = report() ? setTimeout(flush, REFUSAL_REPORT_INTERVAL_MS).unref() : undefined;
  };
  server.on('drop', () => {
    refused += 1;
    if (!windowTimer) flush();
  });
  // Refusals still waiting for the window to end are reported, not lost.
  server.on('close', () => {
    clearTimeout(windowTimer);
    windowTimer = undefined;
    report();
  });
}

function handleConnection(guardian: Guardian, agentId: string, socket: Socket, limits: Required<GuardianSocketOptions>): void {
  // Bytes of the current, not yet newline-terminated frame. Kept raw so each byte is scanned
  // once (no rescans on drip-fed input) and a UTF-8 character split across chunks is decoded
  // only once the whole line is in. 0x0a never occurs inside a multibyte character.
  let partial: Buffer | undefined;
  let partialBytes = 0;
  // Read but not yet parsed because the queue was full. At most one chunk: reading is paused.
  let backlog: Buffer | undefined;
  // Responses go out in request order even though handleCall is async.
  let queue = Promise.resolve();
  let inFlight = 0;

  socket.setTimeout(limits.idleTimeoutMs, () => socket.destroy());

  socket.on('data', (chunk: Buffer) => {
    backlog = backlog ? Buffer.concat([backlog, chunk]) : chunk;
    parse();
  });
  socket.on('error', () => socket.destroy());

  /** Parses frames from the backlog until it is empty or the queue is full. */
  function parse(): void {
    while (backlog && !socket.destroyed) {
      if (inFlight >= limits.maxInFlight) {
        socket.pause();
        return;
      }
      const newline = backlog.indexOf(0x0a);
      if (newline === -1) {
        if (partialBytes + backlog.length > MAX_FRAME_BYTES) return void socket.destroy();
        partial ??= Buffer.allocUnsafe(MAX_FRAME_BYTES);
        backlog.copy(partial, partialBytes);
        partialBytes += backlog.length;
        backlog = undefined;
        break;
      }
      const piece = backlog.subarray(0, newline);
      backlog = newline + 1 < backlog.length ? backlog.subarray(newline + 1) : undefined;
      if (partialBytes + piece.length > MAX_FRAME_BYTES) return void socket.destroy();
      let line: string;
      if (partial && partialBytes > 0) {
        piece.copy(partial, partialBytes);
        line = partial.toString('utf8', 0, partialBytes + piece.length);
        partialBytes = 0;
      } else {
        line = piece.toString('utf8');
      }
      const request = parseFrame(line);
      if (!request) return void socket.destroy();
      enqueue(request);
    }
    if (!socket.destroyed) socket.resume();
  }

  function enqueue(request: z.infer<typeof SocketRequest>): void {
    inFlight += 1;
    queue = queue.then(async () => {
      // A request queued before the connection died (e.g. ahead of a bad frame in the same
      // chunk) must not run: nobody would see its result.
      if (!socket.destroyed) await answer(request);
      inFlight -= 1;
      parse();
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
