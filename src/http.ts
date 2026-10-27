import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  bearerAuthChallengeResponse,
  createMcpHandler,
  localhostAllowedHostnames,
  localhostAllowedOrigins,
  type Server,
  validateHostHeader,
  validateOriginHeader,
  verifyBearerToken,
} from '@modelcontextprotocol/server';
import { OAUTH_PATHS, type OAuthServer } from './oauth/server.js';

// Streamable HTTP at /mcp for clients that need a URL. Every request needs the bearer
// token, or with OAuth on, an access token; only the OAuth endpoints are open. Host and
// Origin are checked first (MCP's DNS-rebinding guidance), so a page in the user's browser
// can't reach the server through a rebound name.

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
// OAuth endpoints are reachable without a token, so their bodies are capped far lower.
const OAUTH_BODY_BYTES: Record<string, number> = {
  '/register': 8 * 1024,
  '/authorize': 16 * 1024,
  '/token': 16 * 1024,
  '/revoke': 16 * 1024,
};

export interface HttpOptions {
  factory: () => Server;
  token: string;
  port: number;
  /** Interface to bind. Defaults to 127.0.0.1; tunnels connect to localhost. */
  host?: string;
  /** Extra Host/Origin hostnames to accept, e.g. a tunnel's public name. */
  allowedHosts?: string[];
  /** Serves the OAuth endpoints and accepts their access tokens on /mcp, besides KORDN_TOKEN. */
  oauth?: OAuthServer;
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
  const { oauth } = options;
  const extra = (options.allowedHosts ?? []).map((h) => h.toLowerCase());
  if (oauth) extra.push(oauth.publicUrl.hostname);
  const hosts = [...localhostAllowedHostnames(), ...extra];
  const origins = [...localhostAllowedOrigins(), ...extra];
  const handler = createMcpHandler(options.factory);

  const server = createServer((req, res) => {
    handle(req, res).catch((error: unknown) => {
      // A client hanging up mid-body isn't our error. Otherwise the path only: queries, headers and bodies can hold codes and tokens.
      if (req.complete || !req.socket.destroyed) {
        const message = (error instanceof Error ? error.message : String(error)).replace(/[\r\n]+/g, ' ');
        process.stderr.write(`kordn: internal error in ${pathOf(req)} handling: ${message}\n`);
      }
      if (!res.headersSent) reply(res, 500, 'internal error');
      else res.destroy();
    });
  });

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (!validateHostHeader(req.headers.host, hosts).ok) return refuse(req, res, 403, 'host not allowed');
    if (!validateOriginHeader(req.headers.origin, origins).ok) return refuse(req, res, 403, 'origin not allowed');
    if (oauth) {
      // The public URL as base, so redirects and `iss` are right behind a tunnel.
      const url = new URL(req.url ?? '/', oauth.publicUrl);
      if (OAUTH_PATHS.includes(url.pathname)) return serveOAuth(req, res, url, oauth);
    }
    if (!authorized(req.headers.authorization, expected)) {
      if (!oauth) return refuse(req, res, 401, 'unauthorized', { 'www-authenticate': 'Bearer realm="kordn"' });
      const challenge = await oauthChallenge(req.headers.authorization, oauth);
      if (challenge) return refuseWith(req, res, challenge);
    }
    const url = new URL(req.url ?? '/', 'http://localhost');
    if (url.pathname !== PATH) return refuse(req, res, 404, 'not found');

    if (Number(req.headers['content-length']) > MAX_BODY_BYTES) {
      drain(req);
      return reply(res, 413, 'request too large');
    }
    const body = req.method === 'POST' ? await readBody(req, MAX_BODY_BYTES, () => drain(req)) : undefined;
    if (body === null) return reply(res, 413, 'request too large');

    const abort = new AbortController();
    res.on('close', () => abort.abort());
    const response = await handler.fetch(
      new Request(url, { method: req.method, headers: toHeaders(req), body, signal: abort.signal }),
    );
    await send(res, response);
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

async function serveOAuth(req: IncomingMessage, res: ServerResponse, url: URL, oauth: OAuthServer): Promise<void> {
  const limit = req.method === 'POST' ? OAUTH_BODY_BYTES[url.pathname] : undefined;
  let body: Uint8Array<ArrayBuffer> | undefined;
  if (limit === undefined) {
    // No body expected (GET, OPTIONS, or a method the handler refuses): discard any, within bounds.
    drain(req, REFUSED_DRAIN_BYTES, REFUSED_DRAIN_MS);
  } else {
    // Unauthenticated, so an oversized body gets the refused bounds, not the 64 MiB drain.
    if (Number(req.headers['content-length']) > limit) return refuse(req, res, 413, 'request too large');
    const read = await readBody(req, limit, () => drain(req, REFUSED_DRAIN_BYTES, REFUSED_DRAIN_MS, true));
    if (read === null) return reply(res, 413, 'request too large');
    body = read;
  }
  const response = await oauth.fetch(new Request(url, { method: req.method, headers: toHeaders(req), body }));
  if (!response) return reply(res, 404, 'not found');
  await send(res, response);
}

/** Undefined when the header holds a valid access token for our resource; otherwise the SDK's challenge. */
async function oauthChallenge(header: string | undefined, oauth: OAuthServer): Promise<Response | undefined> {
  const { verifier, resource, resourceMetadataUrl } = oauth;
  try {
    await verifyBearerToken(header, { verifier, expectedResource: resource, resourceMetadataUrl });
    return undefined;
  } catch (error) {
    return bearerAuthChallengeResponse(error, { resourceMetadataUrl });
  }
}

function pathOf(req: IncomingMessage): string {
  try {
    return new URL(req.url ?? '/', 'http://localhost').pathname;
  } catch {
    return '/';
  }
}

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

/** Compares digests so the check takes the same time whatever the token's length. */
function authorized(header: string | undefined, expected: Buffer): boolean {
  const match = /^Bearer +(\S+)$/i.exec(header ?? '');
  return match?.[1] !== undefined && timingSafeEqual(digest(match[1]), expected);
}

/** Null as soon as the body goes over the limit; `drainRest` then discards the rest in the background. */
function readBody(req: IncomingMessage, limit: number, drainRest: () => void): Promise<Uint8Array<ArrayBuffer> | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const onData = (chunk: Buffer) => {
      size += chunk.length;
      if (size <= limit) return void chunks.push(chunk);
      req.off('data', onData).off('end', onEnd);
      drainRest();
      resolve(null);
    };
    const onEnd = () => resolve(new Uint8Array(Buffer.concat(chunks)));
    // A client that disconnects mid-body never sends 'end'; don't leave the request hanging.
    const onClose = () => {
      if (!req.complete) reject(new Error('request aborted'));
    };
    req.on('data', onData).once('end', onEnd).once('error', reject).once('close', onClose);
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

/** refuse() with a ready-made answer, such as the SDK's Bearer challenge. */
async function refuseWith(req: IncomingMessage, res: ServerResponse, response: Response): Promise<void> {
  drain(req, REFUSED_DRAIN_BYTES, REFUSED_DRAIN_MS, true);
  await send(res, response);
}

async function send(res: ServerResponse, response: Response): Promise<void> {
  res.writeHead(response.status, Object.fromEntries(response.headers));
  if (response.body) {
    for await (const chunk of response.body) res.write(chunk);
  }
  res.end();
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
