import { randomUUID } from 'node:crypto';
import { connect } from 'node:net';
import { z } from 'zod';
import type { CallResult, Guardian } from './guardian-api.js';
import { DenyCode, MAX_FRAME_BYTES } from './schema.js';

// Contain mode: the MCP server's side of the guardian Unix socket. One connection per
// call, so a dead or wedged guardian only ever costs the call in flight. Any failure
// (socket down, timeout, bad reply) is INTERNAL_UNAVAILABLE. There is no fallback.

export const DEFAULT_GUARDIAN_TIMEOUT_MS = 10_000;
// Replies can carry 20 transactions of untrusted text, so allow more than a request frame.
const MAX_REPLY_BYTES = 1024 * 1024;
const MAX_TOOL_CHARS = 64;

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
  timeoutMs?: number;
}

/**
 * The agent id argument is ignored: over the socket, the guardian knows the agent from
 * the socket the launcher bound, never from the payload.
 */
export function createGuardianClient(socketPath: string, options: GuardianClientOptions = {}): Guardian['handleCall'] {
  const timeoutMs = options.timeoutMs ?? DEFAULT_GUARDIAN_TIMEOUT_MS;
  return (_agentId, tool, args) => {
    const id = randomUUID();
    return new Promise<CallResult>((resolve) => {
      let buffered = '';
      let settled = false;
      const socket = connect(socketPath);
      const finish = (result: CallResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.destroy();
        resolve(result);
      };
      const timer = setTimeout(() => finish(UNAVAILABLE), timeoutMs);

      socket.setEncoding('utf8');
      socket.on('connect', () => socket.write(`${encodeFrame(id, tool, args)}\n`));
      socket.on('data', (chunk: string) => {
        buffered += chunk;
        const newline = buffered.indexOf('\n');
        if (newline !== -1) return finish(decodeReply(id, buffered.slice(0, newline)));
        if (Buffer.byteLength(buffered, 'utf8') > MAX_REPLY_BYTES) finish(UNAVAILABLE);
      });
      socket.on('error', () => finish(UNAVAILABLE));
      socket.on('close', () => finish(UNAVAILABLE));
    });
  };
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
