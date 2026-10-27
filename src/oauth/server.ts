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
import type { Html } from '../admin/html.js';
import { WindowLimit, sameSecret } from '../admin/session.js';
import type { OAuthAuditEvent } from '../guardian-api.js';
import { AUTH_METHODS, parseClientMetadata } from './client-metadata.js';
import { consentCsp, consentPage, oauthErrorPage } from './pages.js';
import { isValidChallenge, isValidVerifier } from './pkce.js';
import type { AuthorizeRequest, OAuthStore, StoredClient } from './store.js';

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

const WELL_KNOWN_RESOURCE = '/.well-known/oauth-protected-resource';
const WELL_KNOWN_SERVER = '/.well-known/oauth-authorization-server';
const OWNER_FAILURES_PER_MINUTE = 5;
const MAX_STATE_LENGTH = 1024;

export const OAUTH_PATHS: readonly string[] = [
  WELL_KNOWN_RESOURCE, `${WELL_KNOWN_RESOURCE}/mcp`, WELL_KNOWN_SERVER, '/register', '/authorize', '/token', '/revoke',
];

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

/** Every /authorize response is for a browser: no CORS, no framing, no caching. */
const PAGE_HEADERS: Readonly<Record<string, string>> = {
  'Content-Security-Policy': consentCsp(),
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'same-origin',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

function page(status: number, body: Html, headers: Record<string, string> = {}): Response {
  return new Response(body.value, { status, headers: { 'Content-Type': 'text/html; charset=utf-8', ...PAGE_HEADERS, ...headers } });
}

function errorPage(status: number, message: string, headers?: Record<string, string>): Response {
  return page(status, oauthErrorPage(message), headers);
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
  // Apps registered under an earlier public URL (a quick tunnel's, say) can no longer reach us.
  store.pruneOtherIssuers(issuer);
  const registrations = new WindowLimit(10, 60_000, now);
  const ownerFailures = new WindowLimit(OWNER_FAILURES_PER_MINUTE, 60_000, now);

  const oauthMetadata: OAuthMetadata = {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    registration_endpoint: `${issuer}/register`,
    revocation_endpoint: `${issuer}/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: [...AUTH_METHODS],
    revocation_endpoint_auth_methods_supported: [...AUTH_METHODS],
    authorization_response_iss_parameter_supported: true,
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

  /** An absent resource means ours; one trailing slash is tolerated. */
  function isOurResource(value: string | null): boolean {
    return value === null || (value.endsWith('/') ? value.slice(0, -1) : value) === resourceString;
  }

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
    const { client, secret } = store.registerClient(parsed.value, issuer);
    return json(201, {
      client_id: client.id,
      client_id_issued_at: Math.floor(client.createdAt / 1000),
      ...(secret !== null && { client_secret: secret, client_secret_expires_at: 0 }),
      client_name: client.name,
      redirect_uris: client.redirectUris,
      grant_types: parsed.grantTypes,
      response_types: parsed.responseTypes,
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

    if (!isOurResource(params.get('resource'))) return fail(400, 'invalid_target', 'Unknown resource');

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

  /** 303 back to the client; URL.searchParams keeps any query the registered redirect URI already has. */
  function redirectBack(redirectUri: string, params: Record<string, string>, state: string | null): Response {
    const to = new URL(redirectUri);
    for (const [key, value] of Object.entries(params)) to.searchParams.set(key, value);
    if (state !== null) to.searchParams.set('state', state);
    to.searchParams.set('iss', issuer);
    return new Response(null, { status: 303, headers: { Location: to.href, ...PAGE_HEADERS } });
  }

  function showConsent(status: number, client: StoredClient, req: AuthorizeRequest, errors?: string[]): Response {
    const { id, csrf } = store.saveRequest(req);
    const view = { clientName: client.name, redirectHost: new URL(req.redirectUri).host, requestId: id, csrf, errors };
    return page(status, consentPage(view));
  }

  function startAuthorize(url: URL): Response {
    const q = url.searchParams;
    const clientId = q.get('client_id');
    const redirectUri = q.get('redirect_uri');
    const client = clientId === null ? null : store.getClient(clientId);
    // Until the redirect URI is known to be the client's own, errors must not go to it.
    if (!client || redirectUri === null || !client.redirectUris.includes(redirectUri)) {
      return errorPage(400, 'This app is not registered with kordn, or it asked to return to an address it did not register.');
    }
    // Anyone can register a client with any redirect URI, so until the owner has approved one,
    // its errors stay here: otherwise kordn's address would be an open redirect to that URI.
    const reject = (error: string, state: string | null) => client.approvedAt === null
      ? errorPage(400, 'This app sent a request kordn cannot accept. Try connecting again from the app.')
      : redirectBack(redirectUri, { error }, state);
    const state = q.get('state');
    // Stored with the pending request; an oversized one isn't echoed back either.
    if (state !== null && state.length > MAX_STATE_LENGTH) return reject('invalid_request', null);
    const challenge = q.get('code_challenge');
    if (q.get('response_type') !== 'code') return reject('unsupported_response_type', state);
    if (challenge === null || !isValidChallenge(challenge) || q.get('code_challenge_method') !== 'S256') return reject('invalid_request', state);
    if (!isOurResource(q.get('resource'))) return reject('invalid_target', state);
    return showConsent(200, client, { clientId: client.id, redirectUri, codeChallenge: challenge, resource: resourceString, state });
  }

  async function decideAuthorize(request: Request): Promise<Response> {
    // http.ts checks Origin too; this keeps the handler safe on its own.
    if (request.headers.get('origin') !== issuer) return errorPage(403, 'This request did not come from the kordn approval page.');
    const params = await form(request);
    if (!params) return errorPage(400, 'This request did not come from the kordn approval page.');
    const decision = params.get('decision');
    // Checked before takeRequest so a malformed post doesn't use up the request.
    if (decision !== 'approve' && decision !== 'deny') return errorPage(400, 'Choose Approve or Deny.');
    const req = store.takeRequest(params.get('request') ?? '', params.get('csrf') ?? '');
    if (!req) return errorPage(400, 'This approval page has expired or was already used. Start connecting again from the app.');
    // The client may have been evicted, pruned or revoked while the page was open; approve() would throw.
    const client = store.getClient(req.clientId);
    if (!client) return errorPage(400, 'This app is no longer registered. Start connecting again from the app.');
    // The host the consent page showed the owner, not necessarily the client's first redirect URI.
    const app = { client: client.name, redirectHost: new URL(req.redirectUri).host };
    const isOwner = sameSecret(params.get('owner_token'), options.ownerToken);

    if (decision === 'deny') {
      // Anyone may deny, but only the owner's denial goes into the append-only audit log; wrong tokens here aren't counted.
      if (isOwner) audit('oauth.denied', app);
      return redirectBack(req.redirectUri, { error: 'access_denied' }, req.state);
    }
    // The correct token always passes, even while wrong ones are locked out.
    if (!isOwner) {
      if (ownerFailures.full()) return showConsent(429, client, req, ['Too many wrong tokens. Wait a minute.']);
      ownerFailures.add();
      return showConsent(401, client, req, ['Wrong KORDN_TOKEN.']);
    }
    const approved = store.approve(req);
    if (!approved.ok) return errorPage(409, 'kordn already has 20 connected apps. Revoke one under Apps in the admin UI (start kordn with --admin), then try again.');
    audit('oauth.approved', app);
    return redirectBack(req.redirectUri, { code: approved.code }, req.state);
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
      if (path === '/authorize') {
        if (request.method === 'GET') return startAuthorize(new URL(request.url));
        if (request.method === 'POST') return decideAuthorize(request);
        return errorPage(405, 'Method not allowed.', { Allow: 'GET, POST' });
      }
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
