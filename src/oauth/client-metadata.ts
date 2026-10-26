export type AuthMethod = 'none' | 'client_secret_post' | 'client_secret_basic';
export interface ClientRegistration { name: string; redirectUris: string[]; authMethod: AuthMethod }

const AUTH_METHODS: readonly string[] = ['none', 'client_secret_post', 'client_secret_basic'];
const MAX_REDIRECT_URIS = 5;
const MAX_REDIRECT_URI_LENGTH = 2048;
const MAX_NAME_CODE_POINTS = 100;

/** Control and format characters (bidi overrides, zero-width) have no place in a name shown to the owner. */
export function cleanName(name: string): string {
  const stripped = name.replace(/[\p{Cc}\p{Cf}]/gu, '').trim();
  // Cut by code points so a surrogate pair is never split.
  const cut = Array.from(stripped).slice(0, MAX_NAME_CODE_POINTS).join('').trim();
  return cut || 'Unnamed app';
}

export function isAllowedRedirectUri(uri: string): boolean {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return false;
  }
  if (uri.includes('#') || url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
}

type Parsed =
  | { ok: true; value: ClientRegistration }
  | { ok: false; error: 'invalid_redirect_uri' | 'invalid_client_metadata'; description: string };

const badUri: Parsed = { ok: false, error: 'invalid_redirect_uri', description: 'redirect_uris must be 1 to 5 https or loopback http URIs without fragments' };
const badMeta: Parsed = { ok: false, error: 'invalid_client_metadata', description: 'unsupported client metadata' };

function subsetOf(value: unknown, allowed: readonly string[]): boolean {
  return Array.isArray(value) && value.every((v) => typeof v === 'string' && allowed.includes(v));
}

/** RFC 7591 body → registration, or an RFC 7591 error code with a fixed description. */
export function parseClientMetadata(body: unknown): Parsed {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return badUri;
  const m = body as Record<string, unknown>;
  const uris = m.redirect_uris;
  if (!Array.isArray(uris) || uris.length === 0 || uris.length > MAX_REDIRECT_URIS) return badUri;
  for (const u of uris) {
    if (typeof u !== 'string' || u.length > MAX_REDIRECT_URI_LENGTH || !isAllowedRedirectUri(u)) return badUri;
  }
  if (m.grant_types !== undefined && !subsetOf(m.grant_types, ['authorization_code', 'refresh_token'])) return badMeta;
  if (m.response_types !== undefined && !subsetOf(m.response_types, ['code'])) return badMeta;
  const method = m.token_endpoint_auth_method ?? 'none';
  if (typeof method !== 'string' || !AUTH_METHODS.includes(method)) return badMeta;
  const name = typeof m.client_name === 'string' ? m.client_name : '';
  return { ok: true, value: { name: cleanName(name), redirectUris: [...(uris as string[])], authMethod: method as AuthMethod } };
}
