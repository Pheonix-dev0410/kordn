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
    if (!validateHostHeader(req.headers.host, hosts).ok) return reply(res, 403, 'host not allowed');
    if (!validateOriginHeader(req.headers.origin, origins).ok) return reply(res, 403, 'origin not allowed');
    if (!authorized(req.headers.authorization, expected)) {
      return reply(res, 401, 'unauthorized', { 'www-authenticate': 'Bearer realm="kordn"' });
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== PATH) return reply(res, 404, 'not found');

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

/** Null when the body is over the limit. */
async function readBody(req: IncomingMessage): Promise<Uint8Array<ArrayBuffer> | null> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) return null;
    chunks.push(chunk);
  }
  return new Uint8Array(Buffer.concat(chunks));
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
