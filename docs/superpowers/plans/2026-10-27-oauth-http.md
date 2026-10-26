# OAuth for `kordn --http` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** ChatGPT, claude.ai, Grok and MCP Inspector can connect to `kordn --http` through OAuth 2.1, approved by the owner on a kordn consent page, while `KORDN_TOKEN` keeps working unchanged.

**Architecture:**
- kordn becomes a single-owner OAuth authorization server, plus the MCP resource server it already is, on the same `--http` port.
- State lives in a new private `oauth.sqlite` (`OAuthStore`). The authorization-server endpoints are a web-standard `(Request) => Promise<Response | undefined>` handler, routed from `serveHttp` before the `/mcp` gate.
- `/mcp` accepts `KORDN_TOKEN`, or an access token checked by the SDK's `verifyBearerToken`.
- The admin UI gets a Connected apps page. Audit events go through a new `Guardian` method.

**Tech Stack:** TypeScript (strict, `verbatimModuleSyntax`, `.js` specifiers), Node 24 `node:crypto` + `node:sqlite`, zod 4, `@modelcontextprotocol/server` 2.3.1, vitest.

**Spec:** `docs/superpowers/specs/2026-10-27-oauth-http-design.md`. Read it before any task. Decision numbers below refer to it.

## Global Constraints

- No new dependencies.
- Code style:
  - 2 spaces, single quotes, `.js` import specifiers;
  - sparse "why" comments;
  - fixed reply messages, so nothing from the request is echoed in errors.
- Tokens, codes and client secrets are never stored or logged in plain text. Store `sha256` hex only, and keep them out of audit metadata.
- Every random secret is `secret()` from `src/admin/session.ts` (256 bits, base64url). Every secret comparison goes through `sameSecret` or a hash lookup.
- HTML is built only with the `html` template from `src/admin/html.ts`.
- Lifetimes and caps:

  | Item | Value |
  |---|---|
  | Access token | 3600 s |
  | Code | 60 s, single use |
  | Pending authorize request | 600 s |
  | Refresh token | idle 30 days, rotated on every use |
  | Unapproved clients | pool of 50, evict oldest; pruned after 3600 s |
  | Approved clients | pool of 20 |
  | Registrations | 10 per minute |
  | `/register` body | 8 KiB |
  | Wrong owner tokens | 5 per minute, then a 60 s lock; the correct token always passes |
  | `last_used` writes | at most once per 60 s per grant |

- Redirect URIs are `https:`, or `http:` with hostname `localhost` or `127.0.0.1`. No fragment. Matched byte-for-byte.
- The resource is `<public-url>/mcp` and the issuer is `<public-url>`, where `<public-url>` is an origin with no trailing slash.
- Commits are signed (`git commit -S`), with short imperative subjects ending in `(#36)`. Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Run tests with `direnv exec . npx vitest run <file>`. The full gate is `direnv exec . npm run typecheck && direnv exec . npm test`.

## Review Focus

1. **Chrome applies the consent page's CSP `form-action` to the 303 after Approve.** A `form-action 'self'` CSP blocks the redirect to the app's callback, so connecting silently fails. The consent page CSP must list the redirect URI's origin. Test in Task 6.
2. **A trailing slash on `--public-url` or `resource`** (`https://x.example/` vs `https://x.example`, `…/mcp/`) should be accepted and normalised, not rejected as the wrong audience. Tests in Tasks 4 and 8.
3. **A redirect URI with a query** (`https://app/cb?x=1`) must keep `x=1` when `code`, `state` and `iss` are added. Test in Task 6.
4. **A double-clicked Approve** (the same request id posted twice) issues one code. The second POST gets the error page, with no crash and no second code. Test in Task 6.
5. **A hostile client name** (HTML, 10 KB, control or bidi characters) is escaped, cut to 100 characters and stripped of control characters, both at registration and on every page that shows it. Tests in Tasks 2 and 6.

---

### Task 1: OAuth audit events and the `Guardian` method

**Files:**
- Modify: `src/schema.ts`. Add `'oauth.approved'`, `'oauth.denied'`, `'oauth.revoked'` and `'oauth.refresh_reused'` to the `AuditEvent.event` enum, after `'policy.updated'`.
- Modify: `src/guardian-api.ts`. Add the method to `Guardian`.
- Modify: `src/guardian.ts`. Implement it next to `recordRefusedConnection`.
- Modify: `test/fake-guardian.ts`. Implement it.
- Modify: `src/admin/pages.ts`. Add `apps: ['oauth.approved', 'oauth.denied', 'oauth.revoked', 'oauth.refresh_reused']` to `ACTIVITY_FILTERS`.
- Test: `test/guardian.test.ts`, `test/fake-guardian.test.ts`, `test/schema.test.ts`

**Interfaces:**
- Produces:
  ```ts
  // src/guardian-api.ts
  export type OAuthAuditEvent = 'oauth.approved' | 'oauth.denied' | 'oauth.revoked' | 'oauth.refresh_reused';
  // in interface Guardian:
  /** Logs one audit event as the guardian's own agent. Never rejects. */
  recordOAuthEvent(event: OAuthAuditEvent, app: { client: string; redirectHost: string }): Promise<void>;
  ```
  Metadata is written as `{ client, redirectHost }`. Each value is cut to 100 characters with control characters removed (`/[\p{Cc}\p{Cf}]/gu`). `agent` is the guardian's `agentId`.

- [ ] **Step 1: Write failing tests**
  - `recordOAuthEvent('oauth.approved', { client: 'ChatGPT', redirectHost: 'chatgpt.com' })`: `listActivity({ events: ['oauth.approved'] })` has one event with `metadata` `{ client: 'ChatGPT', redirectHost: 'chatgpt.com' }`, and the audit chain still verifies.
  - A 10 000-character client name is stored as 100 characters, and the call resolves.
  - With a closed or broken ledger, it resolves rather than rejecting.
  - The same assertions hold for the fake guardian.
  - The schema test accepts each of the four new event names.
- [ ] **Step 2: Run them and see them fail.** `direnv exec . npx vitest run test/guardian.test.ts test/fake-guardian.test.ts test/schema.test.ts` should FAIL with "recordOAuthEvent is not a function" or an enum rejection.
- [ ] **Step 3: Implement it.** Follow `recordRefusedConnection`: a ledger transaction, `this.ledger.event(this.agentId, event, …, metadata)`, and `catch {}`.
- [ ] **Step 4: Run them and see them pass**, then run `direnv exec . npm run typecheck`. Every other `Guardian` implementer must compile.
- [ ] **Step 5: Commit.** "Audit OAuth approvals, denials and revocations (#36)"

### Task 2: `OAuthStore`, part 1: clients and registration

**Files:**
- Create: `src/oauth/store.ts`
- Create: `src/oauth/client-metadata.ts`
- Test: `test/oauth-store.test.ts`, `test/oauth-client-metadata.test.ts`

**Interfaces:**
- Produces:
  ```ts
  // src/oauth/client-metadata.ts
  export type AuthMethod = 'none' | 'client_secret_post' | 'client_secret_basic';
  export interface ClientRegistration { name: string; redirectUris: string[]; authMethod: AuthMethod }
  /** RFC 7591 body → registration, or an RFC 7591 error code with a fixed description. */
  export function parseClientMetadata(body: unknown):
    | { ok: true; value: ClientRegistration }
    | { ok: false; error: 'invalid_redirect_uri' | 'invalid_client_metadata'; description: string };
  export function isAllowedRedirectUri(uri: string): boolean;
  export function cleanName(name: string): string; // strips \p{Cc}\p{Cf}, trims, cuts to 100, falls back to 'Unnamed app'

  // src/oauth/store.ts
  export interface StoredClient {
    id: string; name: string; redirectUris: string[]; authMethod: AuthMethod;
    createdAt: number; approvedAt: number | null;
  }
  export class OAuthStore {
    constructor(db: DatabaseSync, now?: () => number);   // creates tables; now defaults to Date.now
    static open(path: string, now?: () => number): OAuthStore; // openPrivateDatabase(path)
    /** Prunes and evicts unapproved clients as needed. The secret is returned only here, and only for secret auth methods. */
    registerClient(reg: ClientRegistration): { client: StoredClient; secret: string | null };
    getClient(id: string): StoredClient | null;
    checkClientSecret(id: string, secret: string | null): boolean; // true for 'none' when secret is null
    close(): void;
  }
  ```
- `parseClientMetadata` rules:
  - `redirect_uris` must be a non-empty array of at most 5 strings, each at most 2048 characters and passing `isAllowedRedirectUri`. Otherwise it fails with `invalid_redirect_uri`.
  - `grant_types` may be absent, or else must be a subset of `['authorization_code', 'refresh_token']`.
  - `response_types` may be absent, or else must be a subset of `['code']`.
  - `token_endpoint_auth_method` may be absent (meaning `'none'`) or one of the three `AuthMethod`s.
  - `client_name` is optional and goes through `cleanName`.
  - Every other field is ignored.
- `isAllowedRedirectUri` accepts a URI only if all of these hold: `new URL()` parses it, it has no `#`, the protocol is `https:` (or `http:` with the hostname exactly `localhost` or `127.0.0.1`), and there are no userinfo credentials.

- [ ] **Step 1: Write failing tests**
  - `isAllowedRedirectUri`:
    - accepts `https://chatgpt.com/connector_platform_oauth_redirect`, `http://localhost:6274/oauth/callback` and `http://127.0.0.1:9/cb`;
    - rejects `http://example.com/cb`, `https://a/cb#x`, `javascript:alert(1)`, `https://u:p@a/cb` and `http://localhost.evil.com/cb`.
  - `parseClientMetadata`:
    - rejects `{}`, `{ redirect_uris: [] }`, six URIs, and `grant_types: ['client_credentials']`;
    - turns a name of `'<b>x</b>‮'.padEnd(500, 'y')` into a 100-character string with no U+202E.
  - Store, registration:
    - registering returns an id of at least 32 characters, and `getClient` round-trips it;
    - `client_secret_post` returns a secret that `checkClientSecret` accepts, and it rejects a wrong secret;
    - `'none'` returns `secret: null`.
  - Store, unapproved pool: with a fake `now`,
    - registering 51 clients leaves 50, and the first is evicted (`getClient` returns null);
    - unapproved clients older than 3600 s are gone on the next register;
    - approved clients are never evicted or pruned. Mark them approved through Task 3's `approve`, or for now with a test-only SQL `UPDATE`.
  - Store, restart: closing and reopening the same file (in a 0700 temp dir) keeps clients.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement it.**
  - Tables are your call, but the client secret is stored as `sha256` hex.
  - `redirectUris` is stored as JSON.
  - Pruning and eviction run inside `registerClient` in one transaction.
- [ ] **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Store OAuth clients with capped open registration (#36)"

### Task 3: `OAuthStore`, part 2: requests, codes, grants and tokens

**Files:**
- Modify: `src/oauth/store.ts`
- Create: `src/oauth/pkce.ts`
- Test: `test/oauth-store.test.ts`, `test/oauth-pkce.test.ts`

**Interfaces:**
- Consumes: Task 2's `OAuthStore` and `StoredClient`.
- Produces:
  ```ts
  // src/oauth/pkce.ts
  /** RFC 7636 §4.1: 43–128 chars of [A-Za-z0-9._~-]. */
  export function isValidVerifier(verifier: string): boolean;
  export function isValidChallenge(challenge: string): boolean; // 43 chars base64url
  export function verifyS256(verifier: string, challenge: string): boolean; // constant-time compare

  // src/oauth/store.ts (additions)
  export interface AuthorizeRequest {
    clientId: string; redirectUri: string; codeChallenge: string; resource: string; state: string | null;
  }
  export interface IssuedTokens { accessToken: string; refreshToken: string; expiresIn: 3600 }
  export interface AccessGrant { clientId: string; resource: string; expiresAt: number /* epoch seconds */ }
  export interface ConnectedApp {
    clientId: string; name: string; redirectHost: string; approvedAt: number; lastUsedAt: number | null;
  }
  export type TokenError = 'invalid_grant' | 'invalid_client';

  // class OAuthStore additions:
  /** Server-side pending request, 600 s TTL. The id goes in the form; the CSRF token is checked with sameSecret. */
  saveRequest(req: AuthorizeRequest): { id: string; csrf: string };
  /** Single use: the second call with the same id returns null. Expired → null. */
  takeRequest(id: string, csrf: string): AuthorizeRequest | null;
  /** Marks the client approved and issues a 60 s code. 'full' when 20 other clients are already approved. */
  approve(req: AuthorizeRequest): { ok: true; code: string } | { ok: false; error: 'full' };
  /** Code + PKCE → tokens. Reusing a code revokes the grant it created. */
  exchangeCode(input: { code: string; clientId: string; redirectUri: string; verifier: string; resource: string }):
    { ok: true; tokens: IssuedTokens } | { ok: false; error: TokenError };
  /** Rotates. Presenting an already-rotated refresh token deletes the grant and returns its client as `reused`. */
  refresh(input: { refreshToken: string; clientId: string; resource: string }):
    { ok: true; tokens: IssuedTokens } | { ok: false; error: TokenError; reused?: StoredClient };
  /** Null for unknown, expired or revoked tokens. Updates last_used at most once per 60 s. */
  verifyAccess(token: string): AccessGrant | null;
  /** RFC 7009: revokes the grant behind an access or refresh token of this client. Unknown → no-op. */
  revokeToken(token: string, clientId: string): void;
  /** Deletes the client, its grants, codes and tokens. Returns the deleted client or null. */
  revokeClient(clientId: string): StoredClient | null;
  /** Approved clients, newest approval first. redirectHost is the host of the first redirect URI. */
  listApps(): ConnectedApp[];
  ```
- Grant model: one approval creates one grant (client, resource, created, last used). Codes, access tokens and refresh tokens hang off a grant. Deleting a grant kills them all.
- Refresh expires when `now - lastUsedAt > 30 days`. Using the access token also counts as use.
- `exchangeCode` rejects with `invalid_grant` when the code is unknown, expired or used, or when the `redirectUri`, `clientId` or `resource` doesn't match, or the PKCE check fails.

- [ ] **Step 1: Write failing tests**
  - PKCE: the RFC 7636 Appendix B vector passes (verifier `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`, challenge `E9cXs2tWyQ_ZURpN8hdqmWGjLBfzuIE5Z_V1WJFfF8w`), a wrong verifier fails, and a 42-character verifier is invalid.
  - Requests: `takeRequest` with the right CSRF returns the request once, then null. A wrong CSRF returns null. After 601 s it returns null.
  - Codes:
    - `approve` → `exchangeCode` works once;
    - a second exchange of the same code gives `invalid_grant`, and the access token from the first is now rejected by `verifyAccess`;
    - a code at 61 s gives `invalid_grant`;
    - a wrong `redirectUri`, `clientId`, `resource` or verifier each gives `invalid_grant`.
  - Approved pool: after 20 approved clients, `approve` for a 21st returns `{ ok: false, error: 'full' }`. Approving an already-approved client still works.
  - Access tokens:
    - `verifyAccess` returns `{ clientId, resource, expiresAt }` with `expiresAt = floor(now/1000) + 3600`;
    - it returns null at 3601 s;
    - it returns null after `revokeClient` and after `revokeToken`.
  - Refresh:
    - a refresh gives new tokens, and the old access token still works until it expires;
    - presenting the old refresh token again → `{ ok: false, error: 'invalid_grant', reused: <client> }`, after which the new refresh token and the new access token are both dead;
    - a refresh after 30 days plus 1 s of idle → `invalid_grant`.
  - `listApps` shows the name, `redirectHost` (`chatgpt.com`), `approvedAt` and `lastUsedAt`. `lastUsedAt` changes after `verifyAccess` only when at least 60 s have passed.
  - Restart: tokens issued before reopening the file still verify.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement it.** Store only hashes. Any multi-row change (exchange, refresh, revoke, reuse kill) runs in one transaction.
- [ ] **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Issue, rotate and revoke OAuth tokens (#36)"

### Task 4: Metadata, `/register`, `/token` and `/revoke`

**Files:**
- Create: `src/oauth/server.ts`
- Test: `test/oauth-server.test.ts` (calls the handler directly with `new Request(...)`, without a socket)

**Interfaces:**
- Consumes: `OAuthStore` (Tasks 2–3), `parseClientMetadata`, `isValidVerifier`, `Guardian['recordOAuthEvent']`, and the SDK exports `oauthMetadataResponse`, `buildOAuthProtectedResourceMetadata`, `getOAuthProtectedResourceMetadataUrl` and `type OAuthMetadata`.
- Produces:
  ```ts
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
    /** <public-url>/mcp */
    resource: URL;
    /** For the 401 challenge on /mcp. */
    resourceMetadataUrl: string;
    /** For verifyBearerToken: reads the store, throws OAuthError(InvalidToken) on null. */
    verifier: OAuthTokenVerifier;
  }
  export const OAUTH_PATHS: readonly string[]; // every path fetch() may answer, for http.ts body caps
  export function createOAuthServer(options: OAuthServerOptions): OAuthServer;
  /** For the CLI: an https origin (http only on localhost/127.0.0.1), with no path beyond "/", no query and no fragment. Returns the bare origin, or null. */
  export function parsePublicUrl(value: string): URL | null;
  ```
- Behaviour:
  - **Metadata.** Use `oauthMetadataResponse` with
    - `oauthMetadata`: issuer `<public-url>`; `authorization_endpoint`, `token_endpoint`, `registration_endpoint` and `revocation_endpoint` under it;
    - `response_types_supported: ['code']`, `grant_types_supported: ['authorization_code', 'refresh_token']`, `code_challenge_methods_supported: ['S256']`;
    - `token_endpoint_auth_methods_supported`: the three methods;
    - `revocation_endpoint_auth_methods_supported` the same;
    - `resourceServerUrl: resource`, `resourceName: 'kordn'`, and `dangerouslyAllowInsecureIssuerUrl` only when the public URL is `http:` on localhost.

    Check whether it serves both `/.well-known/oauth-protected-resource` and `…/mcp`. If it serves only one, add the other.
  - **`POST /register`.**
    - The body is JSON, at most 8 KiB (http.ts caps it, but re-check `content-type` is JSON).
    - It is rate-limited to 10 per minute with `WindowLimit`; over the limit returns 429 `{ error: 'temporarily_unavailable' }`.
    - Success returns 201 with RFC 7591 fields: `client_id`, `client_id_issued_at`, `client_name`, `redirect_uris`, `grant_types`, `response_types` and `token_endpoint_auth_method`, plus `client_secret` (and `client_secret_expires_at: 0`) for secret methods.
    - Errors return 400 with an RFC 7591 error body.
  - **`POST /token`.**
    - The body is form-encoded. Client auth follows the client's `authMethod`: Basic header, `client_id` + `client_secret` in the form, or just `client_id`. A mismatch returns 401 `invalid_client`.
    - `grant_type=authorization_code` needs `code`, `redirect_uri`, `code_verifier` (must pass `isValidVerifier`) and optional `resource`. `grant_type=refresh_token` needs `refresh_token` and optional `resource`.
    - A missing `resource` means `<public-url>/mcp`. A present `resource` is normalised (one trailing slash dropped) and must equal it, or the request fails with `invalid_target`.
    - On a `reused` refresh, it calls `audit('oauth.refresh_reused', …)`.
    - Success returns `{ access_token, token_type: 'Bearer', expires_in: 3600, refresh_token }`.
    - Any other `grant_type` returns `unsupported_grant_type`.
    - Every response from this endpoint carries `Cache-Control: no-store`.
  - **`POST /revoke`.** Form-encoded `token`, with the same client auth. It always returns 200 with an empty body, except for a client-auth failure (401).
  - **CORS.** The metadata, `/register`, `/token` and `/revoke` responses send `Access-Control-Allow-Origin: *`. `OPTIONS` on those paths returns 204 with `Access-Control-Allow-Methods: GET, POST, OPTIONS` and `Access-Control-Allow-Headers: authorization, content-type, mcp-protocol-version`. There are no cookies, so `*` is safe.
  - The verifier returns `AuthInfo { token, clientId, scopes: [], expiresAt, resource: new URL(grant.resource) }`.

- [ ] **Step 1: Write failing tests**
  - Metadata:
    - both protected-resource paths return `resource: '<public>/mcp'` and `authorization_servers: ['<public>']`;
    - the AS metadata has `code_challenge_methods_supported: ['S256']` and the four endpoints;
    - a public URL given as `https://x.example/` normalises to `https://x.example`.
  - `parsePublicUrl`:
    - accepts `https://x.example`, `https://x.example/` and `http://localhost:3333`;
    - rejects `http://x.example`, `https://x.example/path`, `https://x.example?q` and `ftp://x`.
  - Register: 201 with the RFC 7591 fields; 400 `invalid_redirect_uri` for `http://evil/cb`; the 11th within a minute gets 429. Registering never calls `audit` (decision 5).
  - Token:
    - full code flow → 200 with the exact field set and `cache-control: no-store`;
    - a missing `code_verifier` → `invalid_request`;
    - a wrong verifier → `invalid_grant`;
    - code reuse → `invalid_grant`, and `verifier.verifyAccessToken(firstAccess)` rejects;
    - `resource=https://other/mcp` → `invalid_target`;
    - `resource=<public>/mcp/` is accepted;
    - a `client_secret_basic` client with no Basic header → 401 `invalid_client`;
    - refresh-token reuse → `invalid_grant`, with `audit` called once with `'oauth.refresh_reused'`.
  - Revoke: after `/revoke` with the access token, the verifier rejects it. An unknown token → 200.
  - CORS: `OPTIONS /token` → 204 with the allow headers.
  - `fetch(new Request('http://x/mcp'))` → `undefined`.
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement it.** JSON errors are `{ error, error_description? }` with fixed descriptions.
- [ ] **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Serve OAuth metadata, registration, token and revocation endpoints (#36)"

### Task 5: Consent and error pages

**Files:**
- Create: `src/oauth/pages.ts`
- Test: `test/oauth-pages.test.ts`

**Interfaces:**
- Consumes: `html`, `Html` from `src/admin/html.ts`.
- Produces:
  ```ts
  export interface ConsentView {
    clientName: string; redirectHost: string; requestId: string; csrf: string;
    errors?: readonly string[];
  }
  export function consentPage(view: ConsentView): Html;
  /** For bad client_id / redirect_uri and other non-redirectable failures. Fixed text only. */
  export function oauthErrorPage(message: string): Html;
  /** CSP for both pages. form-action allows 'self' plus redirectOrigin when given (Chrome checks redirects after a form POST). */
  export function consentCsp(redirectOrigin?: string): string;
  ```
- Page content:
  - The heading says *"An app wants to use kordn"*.
  - It reads: *"It says it is **{clientName}**"* (the name is untrusted, shown as given) and *"After approval you'll be sent to **{redirectHost}**: check that this is the app you just started connecting."*
  - It has a password field `owner_token` labelled "KORDN_TOKEN", plus hidden `request` and `csrf` fields.
  - It has two submit buttons, `name="decision"` with `value="approve"` and `value="deny"`.
  - There are no scripts. Its own inline CSS is allowed by a sha256 hash in the CSP, as in `src/admin/pages.ts`.
  - The CSP is `default-src 'none'`, the style hash, `form-action 'self' <redirectOrigin>`, `frame-ancestors 'none'` and `base-uri 'none'`.

- [ ] **Step 1: Write failing tests**
  - `consentPage({ clientName: '<script>x</script>', … })` contains `&lt;script&gt;` and no `<script`.
  - The page contains the redirect host, the hidden fields and both decision buttons.
  - `consentCsp('https://chatgpt.com')` contains `frame-ancestors 'none'` and `form-action 'self' https://chatgpt.com`.
  - `consentCsp()` has `form-action 'self'` only.
  - The CSS hash in the CSP matches the inline `<style>` bytes.
- [ ] **Step 2: Run them and see them fail.** **Step 3: Implement them.** **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Add the OAuth consent page (#36)"

### Task 6: `GET`/`POST /authorize`

**Files:**
- Modify: `src/oauth/server.ts`
- Test: `test/oauth-server.test.ts`

**Interfaces:**
- Consumes: Task 5 pages, `OAuthStore.saveRequest`, `takeRequest` and `approve`, `sameSecret`, `WindowLimit`.
- Produces: no new exports. `OAuthServer.fetch` now also answers `/authorize`.
- **`GET /authorize`, in this order:**
  1. An unknown `client_id`, or a `redirect_uri` not byte-for-byte in the client's list, → 400 `oauthErrorPage`. **No redirect.**
  2. Any further error redirects (303) to `redirect_uri` with `error`, `state` (if given) and `iss=<public-url>` added through `URL.searchParams`, which keeps the existing query:
     - `response_type` isn't `code` → `unsupported_response_type`;
     - `code_challenge` is missing or invalid, or `code_challenge_method` isn't `S256` → `invalid_request`;
     - `resource` is present and normalises to something other than the resource → `invalid_target`.
  3. Otherwise `saveRequest` and 200 `consentPage`.
- **`POST /authorize`** (form-encoded, at most 16 KiB):
  1. `takeRequest(request, csrf)`; null → 400 `oauthErrorPage('This approval page has expired or was already used. Start connecting again from the app.')`.
  2. `decision=deny` → `audit('oauth.denied')`, then 303 to the redirect URI with `error=access_denied`, `state` and `iss`.
  3. `decision=approve`:
     - If `owner_token` is wrong, the lock check runs before anything is counted. Locked (5 failures in the current 60 s window) → 429 consent page with *"Too many wrong tokens. Wait a minute."*. Otherwise count a failure and return 401 consent page with *"Wrong KORDN_TOKEN."*. Either way, re-save the request with `saveRequest` so the owner can retry with a fresh id and CSRF token.
     - A correct token always proceeds, even during the lock.
     - `approve()` returning `full` → 409 `oauthErrorPage('kordn already has 20 connected apps. Revoke one in the admin UI first.')`.
     - Otherwise `audit('oauth.approved')`, then 303 to the redirect URI with `code`, `state` and `iss`.
- Headers on every `/authorize` response:
  - `Content-Security-Policy: consentCsp(origin of the redirect URI)` (bare `consentCsp()` on error pages);
  - `X-Frame-Options: DENY`, `Referrer-Policy: same-origin`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`.
- The Origin check for POST is done in http.ts (Task 7). Here, also require `request.headers.get('origin') === publicUrl.origin` on POST `/authorize`, and return 403 `oauthErrorPage` otherwise.

- [ ] **Step 1: Write failing tests**
  - An unknown `client_id` → 400, no `location`. A `redirect_uri` with an extra trailing slash or a different query → 400, no `location`.
  - Missing `code_challenge` → 303 to `redirect_uri` with `error=invalid_request` and `state`. `code_challenge_method=plain` → the same.
  - **(Review Focus 3)** `redirect_uri=https://app.example/cb?x=1`: a later approve redirects to a `location` whose query has `x=1`, `code`, `state` and `iss`.
  - A happy GET returns 200 with headers `x-frame-options: DENY`, a CSP containing `frame-ancestors 'none'` and `form-action 'self' https://app.example` **(Review Focus 1)**, and `referrer-policy: same-origin`.
  - The POST approve flow → 303 with a `code` that `/token` exchanges.
  - **(Review Focus 4)** POSTing the same request id twice → the second gets 400 with the expired message, and only one code was issued (an exchange of the first code works; nothing else exists).
  - Deny → 303 with `error=access_denied`, and `audit` is called with `'oauth.denied'`.
  - Lock:
    - 5 wrong tokens → 401 each;
    - the 6th wrong → 429;
    - the correct token during the lock → 303 with a code;
    - after 61 s, a wrong token → 401 again.
  - An Origin header of `https://evil.example` on POST → 403.
  - **(Review Focus 5)** A client registered with an HTML name renders it escaped on the consent page.
- [ ] **Step 2: Run them and see them fail.** **Step 3: Implement it.** **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Ask the owner to approve OAuth clients (#36)"

### Task 7: Route OAuth through `serveHttp` and accept access tokens on `/mcp`

**Files:**
- Modify: `src/http.ts`
- Test: `test/http.test.ts` (keep every existing test passing unchanged), `test/oauth-flow.test.ts` (new, end to end over a real socket)

**Interfaces:**
- Consumes: `OAuthServer`, `OAUTH_PATHS`, and the SDK's `verifyBearerToken` and `bearerAuthChallengeResponse`.
- Produces: `HttpOptions` gains `oauth?: OAuthServer`. When it is set:
  - the public URL's hostname is added to the allowed hosts and its origin to the allowed origins;
  - OAuth paths are routed before the auth gate;
  - `/mcp` auth runs `authorized(header, expected)` first, and if that fails, `verifyBearerToken(header, { verifier, expectedResource: oauth.resource, resourceMetadataUrl: oauth.resourceMetadataUrl })`;
  - on failure, the 401 is `bearerAuthChallengeResponse(error, { resourceMetadataUrl })`, sent through `refuse()` with its status, `www-authenticate` header and body.
- Without `oauth`, behaviour is byte-identical to today.
- Body caps for OAuth paths:
  - `/register` 8 KiB;
  - `/authorize`, `/token` and `/revoke` 16 KiB;
  - GET and OPTIONS have no body.

  Over the cap → 413 via the existing `drain` path. Generalise `readBody` to take a limit.
- The Request passed to `oauth.fetch` uses the public URL as its base (`new URL(req.url, oauth.publicUrl)`), so redirects and `iss` are right behind a tunnel.

- [ ] **Step 1: Write failing tests** (`test/oauth-flow.test.ts` starts `serveHttp` with `oauth: createOAuthServer({ store: new OAuthStore(new DatabaseSync(':memory:')), publicUrl: new URL('http://localhost:<port>'), … })`; the port comes from a first listen or a fixed free port helper.)
  - With no Authorization header, `/mcp` → 401 whose `www-authenticate` contains `resource_metadata="http://localhost:<port>/.well-known/oauth-protected-resource/mcp"`.
  - Full flow over HTTP: register → GET `/authorize` → parse `request` and `csrf` from the HTML → POST approve (with an Origin header) → `/token` → MCP `Client` with `StreamableHTTPClientTransport` and `requestInit.headers.Authorization: Bearer <access>` → `listTools()` succeeds.
  - Each of these gives a 401 with `resource_metadata`:
    - an expired access token (fake `now` +3601 s);
    - a revoked one (`store.revokeClient`);
    - a wrong-audience one (a token whose grant resource is `https://other/mcp`, inserted through the store with a different `publicUrl` server sharing the same store).
  - `KORDN_TOKEN` still works on `/mcp` with OAuth on.
  - `POST /register` with a 9 KiB body → 413.
  - An Origin of `https://evil.example` on `POST /authorize` → 403 from the http.ts origin check.
  - Without `oauth`, `GET /.well-known/oauth-protected-resource` is still refused before auth (401, as today).
- [ ] **Step 2: Run them and see them fail.**
- [ ] **Step 3: Implement it.**
- [ ] **Step 4: Run `direnv exec . npx vitest run test/http.test.ts test/oauth-flow.test.ts` and see it pass.**
- [ ] **Step 5: Commit.** "Accept OAuth access tokens on /mcp (#36)"

### Task 8: CLI `--public-url`

**Files:**
- Modify: `src/index.ts` (`USAGE`, `Options`, `parse`, `serve`)
- Test: `test/cli.test.ts`

**Interfaces:**
- Consumes: `parsePublicUrl`, `createOAuthServer`, `OAuthStore.open`, `defaultDataDir`, and `guardian.recordOAuthEvent`.
- Produces: `Options.publicUrl?: URL`. `RunningAdmin`/`startAdmin` pass the store through to the admin server (Task 9 adds the option; here, pass nothing).
- Rules:
  - `--public-url` without `--http` → UsageError `'--public-url needs --http'`.
  - With `--guardian` → `'--public-url and --guardian conflict: OAuth state lives where the guardian runs'`.
  - A bad URL → `'--public-url takes an https origin, e.g. https://kordn.example.net (http only for localhost)'`.
- `USAGE` line: `--public-url <url>      turn on OAuth for apps like ChatGPT and claude.ai; the tunnel's https origin`.
- In `serve`: open `OAuthStore.open(join(options.data ?? defaultDataDir(), 'oauth.sqlite'))` after `openGuardian`, which has created the 0700 dir. Close it in the closers. `audit` is `(e, app) => void guardian.recordOAuthEvent(e, app)`. Print `kordn: OAuth on for <public-url>/mcp` to stderr.

- [ ] **Step 1: Write failing tests** (follow the existing spawn-the-CLI pattern in `test/cli.test.ts`):
  - `--public-url https://x.example` alone → exit 2, message contains `needs --http`.
  - With `--guardian /tmp/s` → exit 2, `conflict`.
  - `--public-url http://x.example` → exit 2.
  - `--http --public-url https://x.example/` with `KORDN_TOKEN` and a temp `--data` → stderr shows `OAuth on for https://x.example/mcp` **(Review Focus 2)**, and `oauth.sqlite` exists in the data dir with mode 0600.
- [ ] **Step 2: Run them and see them fail.** **Step 3: Implement it.** **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "Turn on OAuth with --public-url (#36)"

### Task 9: Connected apps in the admin UI

**Files:**
- Modify: `src/admin/server.ts`, `src/admin/pages.ts`, `src/index.ts` (pass the store to `startAdmin`)
- Test: `test/admin-server.test.ts` (or a new `test/admin-apps.test.ts` using `test/admin-helpers.ts`)

**Interfaces:**
- Consumes: `OAuthStore.listApps`, `revokeClient`, `Guardian.recordOAuthEvent`.
- Produces:
  ```ts
  // src/admin/server.ts
  export interface ConnectedApps {
    list(): ConnectedApp[];
    revoke(clientId: string): StoredClient | null;
  }
  // AdminServerOptions gains: apps?: ConnectedApps
  // src/admin/pages.ts
  export function appsPage(ctx: PageContext & { csrf: string }, apps: readonly ConnectedApp[]): Html;
  ```
  `PageContext` gains `apps?: boolean`, which adds an "Apps" nav link.
- Routes, only when `apps` is set (otherwise 404):
  - `GET /apps` shows a table with Name, Redirect host, Approved, Last used (ISO time, or "never") and a Revoke form per row (hidden `client` and `csrf`).
  - `POST /apps/revoke` runs `revoke(client)`. On success it calls `guardian.recordOAuthEvent('oauth.revoked', { client: name, redirectHost })`, sets the flash *"Revoked {name}. It has to be approved again to reconnect."* and redirects with 303 to `/apps`. An unknown client → 409 with the error *"That app is already gone."*.
  - The `hiddenField` length rule applies to `client`.

- [ ] **Step 1: Write failing tests**
  - Logged in with `apps` set: `/apps` lists a seeded app with escaped name and redirect host.
  - Revoke POST with CSRF → 303. The app is gone from the list, `listActivity` has `oauth.revoked`, and the store's access token no longer verifies.
  - A bad CSRF → 403.
  - Without `apps`, `/apps` → 404 and no "Apps" nav link.
- [ ] **Step 2: Run them and see them fail.** **Step 3: Implement it.** **Step 4: Run them and see them pass.**
- [ ] **Step 5: Commit.** "List and revoke connected apps in the admin UI (#36)"

### Task 10: Docs, threat model and the Inspector check

**Files:**
- Modify: `README.md` (the section "ChatGPT, Grok, and other clients that need a URL" at about lines 47–58, and the admin UI section)
- Modify: `docs/threat-model.md` (the "Attacks we test" table and "Known limits")

- [ ] **Step 1: README.**
  - Split the section into "Codex, Cursor and clients that take a token", which stays unchanged, and "ChatGPT, claude.ai and Grok (OAuth)".
  - The OAuth section covers:
    - starting a tunnel (e.g. `cloudflared tunnel --url http://localhost:3333`);
    - running `KORDN_TOKEN=… node dist/index.js --http --public-url https://<tunnel-host>`;
    - adding the connector at `https://<tunnel-host>/mcp`, with a short numbered list for each app: ChatGPT (Settings → Connectors, developer mode), claude.ai (Settings → Connectors → Add custom connector) and Grok;
    - on the consent page, checking the redirect host and pasting `KORDN_TOKEN`;
    - the connector showing up on the phone app under the same account;
    - revoking in the admin UI's Apps page;
    - local testing with MCP Inspector (`npx @modelcontextprotocol/inspector`, transport Streamable HTTP, URL `http://localhost:3333/mcp`, `--public-url http://localhost:3333`).
  - Mark the per-app steps as "to be confirmed by the owner's live test".
- [ ] **Step 2: Threat model rows** (Attack | Expected result | Test):
  - stolen or expired or revoked access token → 401 `resource_metadata`;
  - token for another resource → 401;
  - code replay → `invalid_grant`, and the grant is revoked;
  - PKCE missing, `plain` or wrong → refused;
  - a `redirect_uri` not registered → error page, never redirects;
  - consent framed → `frame-ancestors 'none'`;
  - guessing `KORDN_TOKEN` on the consent page → 5 per minute;
  - refresh token replay → the grant is killed and audited;
  - registration flood → oldest unapproved evicted, approved untouched.

  Each row points to its `oauth-*.test.ts`.
- [ ] **Step 3: Known limits line.** "With `--public-url` behind a tunnel, the consent page is public: anyone who finds the URL can try owner tokens at 5 per minute, and can register up to 50 throwaway clients. The token is 32+ random characters, so guessing is hopeless; the cap only bounds noise."
- [ ] **Step 4: Full gate.** Run `direnv exec . npm run typecheck && direnv exec . npm test`. All pass (Docker-gated tests are skipped as usual).
- [ ] **Step 5: MCP Inspector check (manual, by the implementer).**
  1. Run `npm run build`, then `KORDN_TOKEN=$(openssl rand -hex 32) node dist/index.js --http --public-url http://localhost:3333 --admin`.
  2. Run `npx -y @modelcontextprotocol/inspector`, connect over Streamable HTTP to `http://localhost:3333/mcp`, and complete OAuth with the paste.
  3. `tools/list` and a mock transfer must succeed, and the app must show on the admin Apps page.

  Write down anything Inspector needed that the tests didn't cover (CORS, metadata paths), and fix it with a test.
- [ ] **Step 6: Commit.** "Document OAuth connectors and their threats (#36)"
