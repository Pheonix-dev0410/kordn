# OAuth for `kordn --http` (issue #36)

## Why

ChatGPT, claude.ai and Grok connect to remote MCP servers only through OAuth. They have no
field for a static bearer token. Today `kordn --http` accepts only `KORDN_TOKEN`, so those
apps can't use kordn at all, on the web or on the phone. The goal is for the owner to add
kordn as a connector in each app once, approve it on a kordn page, and then use it from any
device where the app is signed in.

kordn becomes both the MCP resource server and a tiny OAuth 2.1 authorization server for a
single owner. Nothing is hosted, and there's no third-party login.

## Goals

- ChatGPT (dev mode), claude.ai and Grok can connect through a tunnel, complete OAuth and
  make a test transfer. The connector then works from the phone.
- MCP Inspector completes the OAuth flow locally.
- `KORDN_TOKEN` bearer auth keeps working exactly as today (Codex, Cursor).
- The owner can see connected apps and revoke them in the admin UI.

## Non-goals

- A hosted service, third-party login, more than one user, or fine-grained scopes.
- Client ID metadata documents (URL-shaped `client_id`s). Dynamic client registration only.
- Tokens that grant anything beyond kordn's own MCP endpoint. There's no passthrough to
  Razorpay or Stripe.

## Anti-goals (failure even if it "works")

- The consent page or a bad request can redirect to an attacker's URL.
- Any token (owner, access, refresh, code) is written to disk in plain text, logged, echoed
  in a reply or put in audit metadata.
- The consent page can be framed, or a form on it submitted cross-site.
- Spam registrations can grow storage without bound or lock the owner out.
- `KORDN_TOKEN` users see any change in behaviour.

## Constraints

- No new dependencies. Use `node:crypto`, `node:sqlite` and the already-pinned
  `@modelcontextprotocol/server` 2.3.1.
- Follow the existing code style and the hardening patterns in `src/http.ts`: Host/Origin
  checks first, body caps, `refuse()` with drain, and fixed reply messages.
- HTML goes through `src/admin/html.ts` (`html` template, escaping).
- Signed commits on branch `rzzdr/36-oauth`, shipped as one PR that closes #36.

## Decisions (made by the owner)

1. **CLI.** `--public-url <url>` alone turns OAuth on. It requires `--http`. It sets the
   issuer and resource URL, and adds its host to the allowed Host/Origin list (on top of any
   `--allowed-host`). Local testing uses `--public-url http://localhost:<port>`. Without it,
   `--http` behaves exactly as today.
2. **Storage.** A new `oauth.sqlite` in the data dir, opened with `openPrivateDatabase`. It's
   separate from the guardian's `ledger.sqlite`. It holds clients, pending authorization
   requests, codes and grants, with only sha256 hashes of every token or code.
3. **Verifying on `/mcp`.** Check `KORDN_TOKEN` first with the existing constant-time path.
   Otherwise use the SDK's `verifyBearerToken` with our own `OAuthTokenVerifier` and
   `expectedResource`. Build protected-resource metadata with
   `buildOAuthProtectedResourceMetadata`. The authorization-server endpoints are hand-rolled,
   since the SDK has none.
4. **Lifetimes.** Access tokens last 1 h. Codes last 60 s and are single use. Refresh tokens
   rotate on every use and expire after 30 days unused. Presenting an already-rotated refresh
   token revokes the whole grant.
5. **Audit.** Add `oauth.approved`, `oauth.denied`, `oauth.revoked` and
   `oauth.refresh_reused` to the `AuditEvent` enum in `src/schema.ts`, in this PR. Add one
   method to the shared `Guardian` interface for recording OAuth events, updating
   `src/guardian-api.ts`, `src/guardian.ts` and `test/fake-guardian.ts`. Flag both changes
   for immortal1405 in the PR body.
   - Registrations are **not** audited. They're unauthenticated, and the hash-chained log can
     never be pruned.
   - The metadata holds the client name and redirect host, never tokens. The client name is
     truncated to fit `AuditLog`'s 256-character limit.
   - `agent` is the policy's `agentId`.
6. **Revoking.** A new "Connected apps" page in the existing `--admin` UI lists name, redirect
   host, approved at and last used, each with a CSRF-protected Revoke button. Revoking takes
   effect at once, because `/mcp` reads the same store. There's no CLI.
7. **Registration.** `POST /register` (RFC 7591) is open but capped so a flood can't lock
   the owner out:
   - an 8 KiB body;
   - 10 registrations per minute;
   - two separate pools. Approved clients are capped at 20, and strangers can't touch that
     pool. Unapproved clients are capped at 50, and when that pool is full the oldest is
     evicted instead of the new one being refused.
   - Unapproved clients are pruned after 1 hour.

   At 10 per minute, a flood needs more than 5 minutes to evict the owner's fresh
   registration, and consent takes the owner under a minute. When the approved pool is full,
   approving another app fails with a clear message until one is revoked.
8. **`POST /revoke`** (RFC 7009) is included.
9. **Proving ownership.** The consent page shows the app's name and redirect host, and asks
   the owner to paste `KORDN_TOKEN`, compared in constant time.
   - Wrong tokens share one global limit: 5 per minute, then a 1-minute lock.
   - During the lock, wrong tokens are refused but the correct token still works. This
     matches the admin UI login, so a stranger with the URL can't stop the owner approving
     apps.
   - Because the correct token always passes, the limiter doesn't slow down a guesser. It
     only changes what a wrong guess sees (429 instead of 401). The real protection is that
     `KORDN_TOKEN` is 32+ random characters, and the docs say so. They don't claim a
     guessing rate.
   - Deny needs no token: the app gets `access_denied`. `oauth.denied` is audited only when
     a correct `KORDN_TOKEN` was entered with it, so strangers can't grow the append-only
     log.
   - Opening the consent page stores a pending request. There are at most 5 pending
     requests per `client_id`, and a 6th evicts that client's oldest. A `state` longer than
     1024 characters is refused with `invalid_request`. Client ids are random and known only
     to the app that registered, so a flood can only churn its own clients' rows.
10. **Identity.** Calls made with an OAuth token act as the policy's `agentId`, exactly like
    `KORDN_TOKEN` calls. Policies and limits are unchanged.
11. **Live checks.** The builder runs MCP Inspector plus automated tests. The owner runs the
    tunnel tests with ChatGPT, claude.ai and Grok, following the README steps.
12. **No OAuth with `--guardian`.** `--public-url` together with `--guardian` is a usage error
    (exit 2), like `--data` and `--admin` already are. That mode has no data dir, no
    in-process guardian and no admin UI, and the connector use case runs kordn directly
    anyway.

## Builder's calls (made during the design, not by the owner)

- **Consent page referrer.** It uses `Referrer-Policy: same-origin`, not `no-referrer`. With
  `no-referrer`, browsers send `Origin: null` on the form POST, which the Origin check
  rejects. The admin UI does the same thing for the same reason. The cross-site redirect to
  the app still carries no referrer.
- **Missing `resource`.** A client that leaves out `resource` gets `<public-url>/mcp` by
  default. A `resource` that is present but different is rejected (`invalid_target`).
- **Scopes.** No scopes are advertised, and any `scope` parameter is ignored.
- **Client authentication at `/token`.** kordn honours the client's registered
  `token_endpoint_auth_method`: `none` (the default), `client_secret_post` or
  `client_secret_basic`. Secrets are stored hashed. PKCE is required either way.
- **Revoking an app** in the admin UI deletes the client and all its tokens, so it has to
  register and be approved again.

## Shape

### Endpoints (all on the `--http` port, only when `--public-url` is set)

| Path | Purpose |
|---|---|
| `GET /.well-known/oauth-protected-resource` and `…/mcp` | RFC 9728 metadata. The resource is `<public-url>/mcp`, and the authorization server is `<public-url>`. |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata. Code flow only, `S256` only, grant types `authorization_code` and `refresh_token`, with registration and revocation endpoints. |
| `POST /register` | DCR. Validates `redirect_uris` and stores the client. |
| `GET /authorize` | Validates the request and renders the consent page. |
| `POST /authorize` | Approve or deny. Checks CSRF, Origin and `KORDN_TOKEN`, then redirects. |
| `POST /token` | `authorization_code` with a PKCE verifier, or `refresh_token`. |
| `POST /revoke` | Revokes the grant behind an access or refresh token. Always returns 200. |
| `/mcp` | Unchanged handler, behind `KORDN_TOKEN` **or** a valid access token. |

A 401 on `/mcp` carries `WWW-Authenticate: Bearer … resource_metadata="<public-url>/.well-known/oauth-protected-resource/mcp"`
when OAuth is on. When it's off, the 401 is exactly as today.

### Authorize rules

- A request with an unknown `client_id`, or a `redirect_uri` that isn't byte-for-byte one of
  the client's registered URIs, gets an error page and **never** redirects.
- Only then are other errors (wrong `response_type`, missing or non-S256
  `code_challenge`, wrong `resource`) sent back to the redirect URI as OAuth errors, with
  `state` echoed.
- Redirect URIs must be `https:`, or `http:` with host `localhost` or `127.0.0.1` for testing.
  Fragments aren't allowed.
- A code is bound to `client_id`, `redirect_uri`, `code_challenge` and `resource`. Using it a
  second time fails and revokes anything already issued from it.
- The consent page sends `Content-Security-Policy` with `frame-ancestors 'none'`, plus
  `X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and `Cache-Control: no-store`.
- The client name is shown as untrusted text ("says it is …"). The redirect host is shown
  beside it as the thing the owner should actually check.

### Pieces

- **OAuth store** (`oauth.sqlite`): clients, pending authorization requests (with a CSRF
  token), codes, grants (client, approved at, last used, idle expiry), and access/refresh
  token hashes linked to a grant.
- **Authorization-server handler**: the endpoints above. It's plugged into `serveHttp`'s
  routing before the `/mcp` auth gate.
- **Verifier**: an `OAuthTokenVerifier` over the store. It returns `AuthInfo` with `resource`
  and `expiresAt` filled in.
- **Admin "Connected apps" page**: list and revoke. `AdminServerOptions` gets an optional
  store, and the page appears only when OAuth is on.
- **Audit**: writes go through the guardian, which owns the audit log, using the new
  `Guardian` method (decision 5).
- **Docs**:
  - README steps for MCP Inspector, ChatGPT (dev mode), claude.ai and Grok, each through a
    tunnel;
  - threat-model attack rows for every case listed under Tests;
  - a known-limits line: the tunnel makes the consent page public, so anyone with the URL can
    try owner tokens at 5 per minute.

### Tests (from the issue)

- A missing, expired, wrong-audience or revoked token gives a 401 with `resource_metadata`.
- PKCE failures (missing, `plain`, wrong verifier) and code reuse are rejected.
- A `redirect_uri` mismatch never redirects.
- Wrong owner tokens are rate-limited and refused during the lock, while the correct token
  still passes.
- Refresh rotation works, and reusing a rotated token kills the grant.
- The consent page can't be framed (headers present), and the form POST works in a real
  browser (Origin isn't `null`).
- The registration caps hold: body size, rate, both pools, eviction of the oldest unapproved
  client, and pruning.
- `--public-url` with `--guardian`, or without `--http`, exits 2.
- Registrations write no audit rows.
- `KORDN_TOKEN` still works with OAuth on and off.

## Left to the builder

- Module layout (e.g. `src/oauth/`), table schemas and the order of commits.
- Exact wording of pages, errors and README text, in the existing tone.
- How to throttle `last used` writes so `/mcp` doesn't write on every request.
- How the authorization request is carried across GET to POST `/authorize`, as long as it's
  server-side and CSRF-bound.
