export type AuthMethod = 'none' | 'client_secret_post' | 'client_secret_basic';
export interface ClientRegistration { name: string; redirectUris: string[]; authMethod: AuthMethod }

export const AUTH_METHODS: readonly AuthMethod[] = ['none', 'client_secret_post', 'client_secret_basic'];
const GRANT_TYPES: readonly string[] = ['authorization_code', 'refresh_token'];
const RESPONSE_TYPES: readonly string[] = ['code'];
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
  // The URL parser drops tabs and newlines, so the stored string and the parsed one could differ.
  if (/[\p{Cc}\s]/u.test(uri) || uri.includes('#') || url.username || url.password) return false;
  if (url.protocol === 'https:') return true;
  return url.protocol === 'http:' && (url.hostname === 'localhost' || url.hostname === '127.0.0.1');
}

type Parsed =
  | { ok: true; value: ClientRegistration; grantTypes: string[]; responseTypes: string[] }
  | { ok: false; error: 'invalid_redirect_uri' | 'invalid_client_metadata'; description: string };

const badUri: Parsed = { ok: false, error: 'invalid_redirect_uri', description: 'redirect_uris must be 1 to 5 https or loopback http URIs without fragments' };
const badMeta: Parsed = { ok: false, error: 'invalid_client_metadata', description: 'unsupported client metadata' };

/**
 * The supported values the client asked for, in our order; all of them when it asked for none. Unknown values are
 * dropped rather than refused (VS Code asks for the device flow too). Null when `required` isn't among them.
 */
function supported(value: unknown, ours: readonly string[], required: string): string[] | null {
  if (value === undefined) return [...ours];
  if (!Array.isArray(value)) return null;
  const kept = ours.filter((v) => value.includes(v));
  return kept.includes(required) ? kept : null;
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
  const grantTypes = supported(m.grant_types, GRANT_TYPES, 'authorization_code');
  const responseTypes = supported(m.response_types, RESPONSE_TYPES, 'code');
  if (!grantTypes || !responseTypes) return badMeta;
  const method = m.token_endpoint_auth_method ?? 'none';
  if (typeof method !== 'string' || !(AUTH_METHODS as readonly string[]).includes(method)) return badMeta;
  const name = typeof m.client_name === 'string' ? m.client_name : '';
  return { ok: true, value: { name: cleanName(name), redirectUris: [...(uris as string[])], authMethod: method as AuthMethod }, grantTypes, responseTypes };
}
