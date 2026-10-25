import { z } from 'zod';
import { DenyCode } from './decision';

// Wire protocol between the untrusted mcp-shim and the trusted guardian over the
// launcher-mounted Unix-domain socket: newline-delimited JSON, one frame per line.
//
// The shim forwards `tool` and `args` UNPARSED; the guardian is the only validator.
// There is deliberately no agentId / policyApproved / identity field: the guardian
// derives identity from which socket the frame arrived on (§4.2, §7.4).

export const IPC_VERSION = 1;
export const MAX_FRAME_BYTES = 64 * 1024;

export const IpcRequest = z.strictObject({
  v: z.literal(IPC_VERSION),
  id: z.string().min(1).max(64),
  tool: z.string().max(64),
  args: z.unknown(),
});
export type IpcRequest = z.infer<typeof IpcRequest>;

export const IpcError = z.strictObject({
  code: DenyCode,
  message: z.string().max(256),
});

export const IpcResponse = z.discriminatedUnion('ok', [
  z.strictObject({ v: z.literal(IPC_VERSION), id: z.string(), ok: z.literal(true), result: z.unknown() }),
  z.strictObject({ v: z.literal(IPC_VERSION), id: z.string(), ok: z.literal(false), error: IpcError }),
]);
export type IpcResponse = z.infer<typeof IpcResponse>;
