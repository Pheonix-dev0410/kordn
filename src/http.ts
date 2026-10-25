import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  createMcpHandler,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  type Server,
  validateHostHeader,
  validateOriginHeader,
} from '@modelcontextprotocol/server';

// Streamable HTTP at /mcp for clients that need a URL. Every request needs the bearer
// token. Host and Origin are checked first (MCP's DNS-rebinding guidance), so a page in
// the user's browser can't reach the server through a rebound name.

export const MIN_TOKEN_LENGTH = 32;
const MAX_BODY_BYTES = 1024 * 1024;
// After a 413, keep reading (and discarding) this much of the body before cutting the
// connection. Closing a socket with unread data makes the kernel send a RST, which can
// destroy the 413 before the client reads it.
const MAX_DRAIN_BYTES = 64 * 1024 * 1024;
const DRAIN_MS = 5_000;
// Refused before auth: read only enough for the client to see the reply, then hang up, so
// nobody unauthenticated can stream into the server.
const REFUSED_DRAIN_BYTES = 64 * 1024;
const REFUSED_DRAIN_MS = 1_000;
const PATH = '/mcp';

export interface HttpOptions {
  factory: () => Server;
  token: string;
  port: number;
  /** Interface to bind. Defaults to 127.0.0.1; tunnels connect to localhost. */
  host?: string;
  /** Extra Host/Origin hostnames to accept, e.g. a tunnel's public name. */
  allowedHosts?: string[];
}

export interface HttpHandle {
  url: string;
  close(): Promise<void>;
}

export async function serveHttp(options: HttpOptions): Promise<HttpHandle> {
  if (options.token.length < MIN_TOKEN_LENGTH) {
    throw new Error(`KORDN_TOKEN must be set to a random secret of at least ${MIN_TOKEN_LENGTH} characters`);
  }
  const expected = digest(options.token);
  const extra = (options.allowedHosts ?? []).map((h) => h.toLowerCase());
  const hosts = [...localhostAllowedHostnames(), ...extra];
  const origins = [...localhostAllowedOrigins(), ...extra];
  const handler = createMcpHandler(options.factory);

  const server = createServer((req, res) => {
    handle(req, res).catch(() => {
      if (!res.headersSent) reply(res, 500, 'internal error');
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!validateHostHeader(req.headers.host, hosts).ok) return refuse(req, res, 403, 'host not allowed');
    if (!validateOriginHeader(req.headers.origin, origins).ok) return refuse(req, res, 403, 'origin not allowed');
    if (!authorized(req.headers.authorization, expected)) {
      return refuse(req, res, 401, 'unauthorized', { 'www-authenticate': 'Bearer realm="kordn"' });
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== PATH) return refuse(req, res, 404, 'not found');

    if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
      drain(req);
      return reply(res, 413, 'request too large');
    }
    const body = req.method === 'POST' ? await readBody(req) : undefined;
    if (body === null) return reply(res, 413, 'request too large');

    const abort = new AbortController();
    res.on('close', () => abort.abort());
    const response = await handler.fetch(
      new Request(url, { method: req.method, headers: toHeaders(req), body, signal: abort.signal }),
    );
    res.writeHead(response.status, Object.fromEntries(response.headers));
    if (response.body) {
      for await (const chunk of response.body) res.write(chunk);
    }
    res.end();
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port, options.host ?? '127.0.0.1', () => {
      server.off('error', reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo;
  const hostPart = address.family === 'IPv6' ? `[${address.address}]` : address.address;

  return {
    url: `http://${hostPart}:${address.port}${PATH}`,
    async close() {
      await handler.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/** Compares digests so the check takes the same time whatever the token's length. */
function authorized(header: string | undefined, expected: Buffer): boolean {
  const match = /^Bearer +(\S+)$/i.exec(header ?? '');
  return match?.[1] !== undefined && timingSafeEqual(digest(match[1]), expected);
}

/** Null as soon as the body goes over the limit; the rest is drained in the background. */
function readBody(req: IncomingMessage): Promise<Uint8Array<ArrayBuffer> | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_BODY_BYTES) return void chunks.push(chunk);
      req.off('data', onData).off('end', onEnd);
      drain(req);
      resolve(null);
    };
    const onEnd = () => resolve(new Uint8Array(Buffer.concat(chunks)));
    req.on('data', onData).once('end', onEnd).once('error', reject);
  });
}

/**
 * Discard the rest of a refused body, within bounds, so the reply isn't lost to a reset.
 * Past the bounds the socket is cut. With `hangUp`, the connection is also closed once the
 * body is in, so it can't be reused.
 */
function drain(req: IncomingMessage, maxBytes = MAX_DRAIN_BYTES, ms = DRAIN_MS, hangUp = false): void {
  let drained = 0;
  const cut = () => req.socket.destroy();
  const timer = setTimeout(cut, ms).unref();
  req.on('data', (chunk: Buffer) => {
    drained += chunk.length;
    if (drained > maxBytes) cut();
  });
  req.once('end', () => {
    clearTimeout(timer);
    if (hangUp) req.socket.end();
  });
  req.once('close', () => clearTimeout(timer));
  req.resume();
}

/**
 * Reply to a request that never gets to the MCP handler and close the connection. Not
 * `Connection: close`: Node would then destroy the socket with the body unread, and the
 * resulting reset can wipe out the reply before the client reads it.
 */
function refuse(
  req: IncomingMessage,
  res: ServerResponse,
  status: number,
  message: string,
  headers: Record<string, string> = {},
): void {
  drain(req, REFUSED_DRAIN_BYTES, REFUSED_DRAIN_MS, true);
  reply(res, status, message, headers);
}

function toHeaders(req: IncomingMessage): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    for (const v of Array.isArray(value) ? value : [value]) headers.append(name, v);
  }
  return headers;
}

// Fixed messages: nothing from the request is echoed back.
function reply(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { 'content-type': 'application/json', ...headers });
  res.end(JSON.stringify({ error: message }));
}
