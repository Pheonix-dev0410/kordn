import { randomUUID } from 'node:crypto';
import { connect, type Socket } from 'node:net';
import { z } from 'zod';
import type { CallResult, Guardian } from './guardian-api.js';
import { DenyCode, MAX_FRAME_BYTES } from './schema.js';

// Contain mode: the MCP server's side of the guardian Unix socket. One connection per
// call, so a dead or wedged guardian only ever costs the call in flight. Any failure
// (socket down, timeout, bad reply) is INTERNAL_UNAVAILABLE. There is no fallback.
// The guardian closes connections past its cap without logging them, so calls beyond
// maxConcurrent wait in a FIFO queue instead of being turned away unlogged.

export const DEFAULT_GUARDIAN_TIMEOUT_MS = 10_000;
// Comfortably under the guardian socket's default of 32 connections.
export const DEFAULT_MAX_CONCURRENT = 16;
// Replies can carry 20 transactions of untrusted text, so allow more than a request frame.
const MAX_REPLY_BYTES = 1024 * 1024;
const MAX_TOOL_CHARS = 64;
// Node clamps a longer timer to 1 ms, which would fail every call at once.
const MAX_TIMER_MS = 2 ** 31 - 1;

const Reply = z.union([
  z.strictObject({ v: z.literal(1), id: z.string(), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({
    v: z.literal(1),
    id: z.string(),
    ok: z.literal(false),
    error: z.strictObject({ code: DenyCode, message: z.string() }),
  }),
]);

const UNAVAILABLE: CallResult = { ok: false, error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' } };

export interface GuardianClientOptions {
  /** Per call, including time spent queued. */
  timeoutMs?: number;
  /** Connections open at once. Further calls queue. */
  maxConcurrent?: number;
}

/**
 * The agent id argument is ignored: over the socket, the guardian knows the agent from
 * the socket the launcher bound, never from the payload.
 */
export function createGuardianClient(socketPath: string, options: GuardianClientOptions = {}): Guardian['handleCall'] {
  const timeoutMs = options.timeoutMs ?? DEFAULT_GUARDIAN_TIMEOUT_MS;
  const maxConcurrent = options.maxConcurrent ?? DEFAULT_MAX_CONCURRENT;
  // 0 or NaN would queue every call until it times out.
  if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1) throw new RangeError(`invalid maxConcurrent: ${maxConcurrent}`);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMER_MS) throw new RangeError(`invalid timeoutMs: ${timeoutMs}`);

  const queue: (() => void)[] = [];
  let active = 0;
  const pump = () => {
    while (active < maxConcurrent && queue.length > 0) {
      active += 1;
      queue.shift()?.();
    }
  };

  return (_agentId, tool, args) =>
    new Promise<CallResult>((resolve) => {
      // Encoded before queueing: args JSON can't encode (a BigInt, a cycle) fail here, before
      // a slot is taken. Over MCP args are parsed JSON, so only direct callers can hit this.
      const id = randomUUID();
      let frame: string;
      try {
        frame = encodeFrame(id, tool, args);
      } catch {
        return resolve(UNAVAILABLE);
      }
      let socket: Socket | undefined;
      let settled = false;
      const finish = (result: CallResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (socket) {
          socket.destroy();
          active -= 1;
          // Deferred so queued calls whose timeout fires in this same tick drop out first,
          // instead of each opening a connection only to close it at once.
          setImmediate(pump);
        } else {
          const queued = queue.indexOf(start);
          if (queued !== -1) queue.splice(queued, 1);
        }
        resolve(result);
      };
      // Started now, not at dispatch: a hung guardian fails queued calls on time too.
      const timer = setTimeout(() => finish(UNAVAILABLE), timeoutMs);
      const start = () => {
        socket = exchange(socketPath, id, frame, finish);
      };
      queue.push(start);
      pump();
    });
}

/** Send one frame on a fresh connection and report the reply, or UNAVAILABLE, exactly once via `finish`. */
function exchange(socketPath: string, id: string, frame: string, finish: (result: CallResult) => void): Socket {
  let buffered = '';
  const socket = connect(socketPath);
  socket.setEncoding('utf8');
  socket.on('connect', () => socket.write(`${frame}\n`));
  socket.on('data', (chunk: string) => {
    buffered += chunk;
    const newline = buffered.indexOf('\n');
    if (newline !== -1) return finish(decodeReply(id, buffered.slice(0, newline)));
    if (Buffer.byteLength(buffered, 'utf8') > MAX_REPLY_BYTES) finish(UNAVAILABLE);
  });
  socket.on('error', () => finish(UNAVAILABLE));
  socket.on('close', () => finish(UNAVAILABLE));
  return socket;
}

/**
 * Args go through unparsed: validation is the guardian's job. Frames the guardian would
 * refuse outright are shrunk instead, so the attempt still reaches it and gets logged:
 * an over-long tool name is truncated (it can't become a real tool name that way) and
 * oversized args are replaced by null (which no tool accepts).
 */
function encodeFrame(id: string, tool: unknown, args: unknown): string {
  const name = typeof tool === 'string' ? tool.slice(0, MAX_TOOL_CHARS) : '';
  // JSON.stringify drops an undefined key, and the guardian refuses a frame without args.
  const frame = JSON.stringify({ v: 1, id, tool: name, args: args === undefined ? null : args });
  if (Buffer.byteLength(frame, 'utf8') <= MAX_FRAME_BYTES) return frame;
  return JSON.stringify({ v: 1, id, tool: name, args: null });
}

function decodeReply(id: string, line: string): CallResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    return UNAVAILABLE;
  }
  const reply = Reply.safeParse(parsed);
  if (!reply.success || reply.data.id !== id) return UNAVAILABLE;
  return reply.data.ok ? { ok: true, result: reply.data.result } : { ok: false, error: reply.data.error };
}
