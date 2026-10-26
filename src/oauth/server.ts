import {
  type AuthInfo,
  buildOAuthProtectedResourceMetadata,
  getOAuthProtectedResourceMetadataUrl,
  OAuthError,
  OAuthErrorCode,
  type OAuthMetadata,
  type OAuthTokenVerifier,
  oauthMetadataResponse,
} from '@modelcontextprotocol/server';
import { WindowLimit } from '../admin/session.js';
import type { OAuthAuditEvent } from '../guardian-api.js';
import { type AuthMethod, parseClientMetadata } from './client-metadata.js';
import { isValidVerifier } from './pkce.js';
import type { OAuthStore, StoredClient } from './store.js';

export interface OAuthServerOptions {
  store: OAuthStore;
  /** Normalised origin, e.g. https://x.trycloudflare.com (no trailing slash). */
  publicUrl: URL;
  ownerToken: string;
  audit: (event: OAuthAuditEvent, app: { client: string; redirectHost: string }) => void;
  now?: () => number;
}

export interface OAuthServer {
  /** Undefined when the path isn't an OAuth path, so the caller falls through to /mcp. */
  fetch(request: Request): Promise<Response | undefined>;
  publicUrl: URL;
  /** <public-url>/mcp */
  resource: URL;
  /** For the 401 challenge on /mcp. */
  resourceMetadataUrl: string;
  /** For verifyBearerToken: reads the store, throws OAuthError(InvalidToken) on null. */
  verifier: OAuthTokenVerifier;
}

const AUTH_METHODS: AuthMethod[] = ['none', 'client_secret_post', 'client_secret_basic'];
const WELL_KNOWN_RESOURCE = '/.well-known/oauth-protected-resource';
const WELL_KNOWN_SERVER = '/.well-known/oauth-authorization-server';

export const OAUTH_PATHS: readonly string[] = [WELL_KNOWN_RESOURCE, `${WELL_KNOWN_RESOURCE}/mcp`, WELL_KNOWN_SERVER, '/register', '/token', '/revoke'];

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'authorization, content-type, mcp-protocol-version',
};

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return Response.json(body, { status, headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store', ...headers } });
}

function fail(status: number, error: string, description?: string): Response {
  return json(status, description === undefined ? { error } : { error, error_description: description });
}

/** For the CLI: an https origin (http only on localhost/127.0.0.1), with no path beyond "/", no query and no fragment. */
export function parsePublicUrl(value: string): URL | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) return null;
  if (url.pathname !== '/' || url.search || value.includes('?') || url.hash || value.includes('#') || url.username || url.password) return null;
  return new URL(url.origin);
}

/** Basic credentials are form-urlencoded before base64 (RFC 6749 §2.3.1). 'bad' for a Basic header that can't be parsed; null when there is none. */
function basicCredentials(header: string | null): { id: string; secret: string } | 'bad' | null {
  if (!header || !/^Basic\b/i.test(header)) return null;
  const match = header.match(/^Basic +([A-Za-z0-9+/=_-]+)$/i);
  if (!match) return 'bad';
  const decoded = Buffer.from(match[1] as string, 'base64').toString('utf8');
  const colon = decoded.indexOf(':');
  if (colon < 0) return 'bad';
  try {
    const form = (s: string) => decodeURIComponent(s.replace(/\+/g, ' '));
    return { id: form(decoded.slice(0, colon)), secret: form(decoded.slice(colon + 1)) };
  } catch {
    return 'bad';
  }
}

export function createOAuthServer(options: OAuthServerOptions): OAuthServer {
  const { store, audit } = options;
  const now = options.now ?? Date.now;
  const issuer = options.publicUrl.origin;
  const resource = new URL('/mcp', issuer);
  const resourceString = resource.href;
  if (!parsePublicUrl(issuer)) throw new Error('publicUrl must be an https origin, or http on localhost');
  const registrations = new WindowLimit(10, 60_000, now);

  const oauthMetadata: OAuthMetadata = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: AUTH_METHODS,
    revocation_endpoint_auth_methods_supported: AUTH_METHODS,
  };
  const metadataOptions = {
    oauthMetadata,
    resourceServerUrl: resource,
    resourceName: 'kordn',
  };

  const verifier: OAuthTokenVerifier = {
    async verifyAccessToken(token): Promise<AuthInfo> {
      const grant = store.verifyAccess(token);
      if (!grant) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid access token');
      return { token, clientId: grant.clientId, scopes: [], expiresAt: grant.expiresAt, resource: new URL(grant.resource) };
    },
  };

  async function form(request: Request): Promise<URLSearchParams | null> {
    if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/x-www-form-urlencoded')) return null;
    return new URLSearchParams(await request.text());
  }

  /**
   * The client when its credentials check out; otherwise the 401 to send. Credentials come from one source:
   * Basic, or the form. A secret-method client may use either; a public client may present no secret at all.
   */
  function authenticate(request: Request, params: URLSearchParams): StoredClient | Response {
    const invalid = () => fail(401, 'invalid_client', 'Client authentication failed');
    const basic = basicCredentials(request.headers.get('authorization'));
    if (basic === 'bad') return invalid();
    const formId = params.get('client_id');
    let id = formId;
    let secret = params.get('client_secret');
    if (basic) {
      if ((formId !== null && formId !== basic.id) || params.has('client_secret')) return invalid();
      id = basic.id;
      secret = basic.secret;
    }
    const client = id === null ? null : store.getClient(id);
    if (!client) return invalid();
    if (client.authMethod === 'none') {
      if (secret) return invalid();
      secret = null;
    }
    return store.checkClientSecret(client.id, secret) ? client : invalid();
  }

  async function register(request: Request): Promise<Response> {
    if (registrations.full()) return fail(429, 'temporarily_unavailable', 'Too many registrations');
    registrations.add();
    if (!request.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
      return fail(400, 'invalid_client_metadata', 'Content-Type must be application/json');
    }
    let body: unknown;
    try {
      body = JSON.parse(await request.text());
    } catch {
      return fail(400, 'invalid_client_metadata', 'Body must be JSON');
    }
    const parsed = parseClientMetadata(body);
    if (!parsed.ok) return fail(400, parsed.error, parsed.description);
    const { client, secret } = store.registerClient(parsed.value);
    return json(201, {
      client_id: client.id,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
      ...(secret !== null && { client_secret: secret, client_secret_expires_at: 0 }),
      client_name: client.name,
      redirect_uris: client.redirectUris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: client.authMethod,
    });
  }

  async function token(request: Request): Promise<Response> {
    const params = await form(request);
    if (!params) return fail(400, 'invalid_request', 'Content-Type must be application/x-www-form-urlencoded');
    const client = authenticate(request, params);
    if (client instanceof Response) return client;

    const grantType = params.get('grant_type');
    if (grantType !== 'authorization_code' && grantType !== 'refresh_token') return fail(400, 'unsupported_grant_type', 'Unsupported grant_type');

    const requested = params.get('resource');
    if (requested !== null && (requested.endsWith('/') ? requested.slice(0, -1) : requested) !== resourceString) {
      return fail(400, 'invalid_target', 'Unknown resource');
    }

    let result;
    if (grantType === 'authorization_code') {
      const code = params.get('code');
      const redirectUri = params.get('redirect_uri');
      const verifierValue = params.get('code_verifier');
      if (!code || !redirectUri || !verifierValue) return fail(400, 'invalid_request', 'Missing code, redirect_uri or code_verifier');
      if (!isValidVerifier(verifierValue)) return fail(400, 'invalid_request', 'Malformed code_verifier');
      result = store.exchangeCode({ code, clientId: client.id, redirectUri, verifier: verifierValue, resource: resourceString });
    } else {
      const refreshToken = params.get('refresh_token');
      if (!refreshToken) return fail(400, 'invalid_request', 'Missing refresh_token');
      result = store.refresh({ refreshToken, clientId: client.id, resource: resourceString });
      if (!result.ok && result.reused) {
        audit('oauth.refresh_reused', { client: result.reused.name, redirectHost: new URL(result.reused.redirectUris[0] as string).host });
      }
    }
    if (!result.ok) {
      return result.error === 'invalid_client' ? fail(401, 'invalid_client', 'Client authentication failed') : fail(400, 'invalid_grant', 'Invalid or expired grant');
    }
    return json(200, {
      access_token: result.tokens.accessToken,
      token_type: 'Bearer',
      expires_in: result.tokens.expiresIn,
      refresh_token: result.tokens.refreshToken,
    });
  }

  async function revoke(request: Request): Promise<Response> {
    const params = await form(request);
    if (!params) return fail(400, 'invalid_request', 'Content-Type must be application/x-www-form-urlencoded');
    const client = authenticate(request, params);
    if (client instanceof Response) return client;
    const value = params.get('token');
    if (value) store.revokeToken(value, client.id);
    return new Response(null, { status: 200, headers: { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store' } });
  }

  const endpoints: Record<string, (request: Request) => Promise<Response>> = {
    '/register': register,
    '/token': token,
    '/revoke': revoke,
  };

  return {
    publicUrl: options.publicUrl,
    resource,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resource),
    verifier,
    async fetch(request) {
      const path = new URL(request.url).pathname;
      if (!OAUTH_PATHS.includes(path)) return undefined;
      if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
      const handler = endpoints[path];
      if (handler) {
        if (request.method !== 'POST') return json(405, { error: 'invalid_request' }, { Allow: 'POST, OPTIONS' });
        return handler(request);
      }
      // The SDK serves the path-suffixed protected-resource document and the AS document; the bare root document is ours.
      if (path === WELL_KNOWN_RESOURCE) {
        if (request.method !== 'GET' && request.method !== 'HEAD') return json(405, { error: 'invalid_request' }, { Allow: 'GET, HEAD, OPTIONS' });
        return Response.json(buildOAuthProtectedResourceMetadata(metadataOptions), { headers: { 'Access-Control-Allow-Origin': '*' } });
      }
      return oauthMetadataResponse(request, metadataOptions);
    },
  };
}
