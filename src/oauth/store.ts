import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { secret as newSecret, sameSecret } from '../admin/session.js';
import { openPrivateDatabase } from '../database.js';
import type { AuthMethod, ClientRegistration } from './client-metadata.js';
import { verifyS256 } from './pkce.js';

const UNAPPROVED_POOL = 50;
const UNAPPROVED_TTL_MS = 3600_000;
const APPROVED_POOL = 20;
const REQUEST_TTL_MS = 600_000;
const REQUESTS_PER_CLIENT = 5;
const CODE_TTL_MS = 60_000;
const ACCESS_TTL_S = 3600;
const REFRESH_IDLE_MS = 30 * 86_400_000;
const LAST_USED_INTERVAL_MS = 60_000;

export interface StoredClient {
  id: string;
  name: string;
  redirectUris: string[];
  authMethod: AuthMethod;
  createdAt: number;
  approvedAt: number | null;
}

export interface AuthorizeRequest {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  state: string | null;
}

export interface IssuedTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: 3600;
}

export interface AccessGrant {
  clientId: string;
  resource: string;
  /** Epoch seconds. */
  expiresAt: number;
}

export interface ConnectedApp {
  clientId: string;
  name: string;
  redirectHost: string;
  approvedAt: number;
  lastUsedAt: number | null;
}

export type TokenError = 'invalid_grant' | 'invalid_client';

interface RequestRow {
  id_hash: string;
  csrf_hash: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  resource: string;
  state: string | null;
  expires_at: number;
}

interface CodeRow {
  hash: string;
  grant_id: string;
  redirect_uri: string;
  code_challenge: string;
  expires_at: number;
  used: number;
  client_id: string;
  resource: string;
}

interface RefreshRow {
  hash: string;
  grant_id: string;
  rotated: number;
  client_id: string;
  resource: string;
  created_at: number;
  last_used_at: number | null;
}

interface AccessRow {
  expires_at: number;
  id: string;
  client_id: string;
  resource: string;
  last_used_at: number | null;
}

interface ClientRow {
  id: string;
  name: string;
  redirect_uris: string;
  auth_method: AuthMethod;
  secret_hash: string | null;
  created_at: number;
  approved_at: number | null;
}

const hex = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex');

export class OAuthStore {
  constructor(
    private readonly db: DatabaseSync,
    private readonly now: () => number = Date.now,
  ) {
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS oauth_clients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        secret_hash TEXT,
        created_at INTEGER NOT NULL,
        approved_at INTEGER,
        issuer TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_requests (
        id_hash TEXT PRIMARY KEY,
        csrf_hash TEXT NOT NULL,
        client_id TEXT NOT NULL,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        resource TEXT NOT NULL,
        state TEXT,
        expires_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_grants (
        id TEXT PRIMARY KEY,
        client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
        resource TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS oauth_codes (
        hash TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        redirect_uri TEXT NOT NULL,
        code_challenge TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        hash TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
        kind TEXT NOT NULL,
        expires_at INTEGER,
        rotated INTEGER NOT NULL DEFAULT 0
      );`);
    // Databases from before clients had an issuer: '' matches no public URL, so their clients get pruned.
    const columns = this.db.prepare('PRAGMA table_info(oauth_clients)').all() as unknown as { name: string }[];
    if (!columns.some((c) => c.name === 'issuer')) this.db.exec("ALTER TABLE oauth_clients ADD COLUMN issuer TEXT NOT NULL DEFAULT ''");
  }

  static open(path: string, now?: () => number): OAuthStore {
    return new OAuthStore(openPrivateDatabase(path), now);
  }

  /**
   * Prunes idle approved clients and grants, and prunes and evicts unapproved clients as needed.
   * `issuer` is the public URL the client registered under. The secret is returned only here, and only for secret auth methods.
   */
  registerClient(reg: ClientRegistration, issuer: string): { client: StoredClient; secret: string | null } {
    const id = newSecret();
    const secret = reg.authMethod === 'none' ? null : newSecret();
    const createdAt = this.now();
    this.tx(() => {
      this.pruneIdle(createdAt);
      this.db.prepare('DELETE FROM oauth_clients WHERE approved_at IS NULL AND created_at < ?').run(createdAt - UNAPPROVED_TTL_MS);
      this.db.prepare('INSERT INTO oauth_clients (id, name, redirect_uris, auth_method, secret_hash, created_at, issuer) VALUES (?, ?, ?, ?, ?, ?, ?)')
        .run(id, reg.name, JSON.stringify(reg.redirectUris), reg.authMethod, secret === null ? null : hex(secret), createdAt, issuer);
      this.db.prepare(`DELETE FROM oauth_clients WHERE approved_at IS NULL AND id IN (
        SELECT id FROM oauth_clients WHERE approved_at IS NULL ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?)`)
        .run(UNAPPROVED_POOL);
    });
    return { client: { id, name: reg.name, redirectUris: [...reg.redirectUris], authMethod: reg.authMethod, createdAt, approvedAt: null }, secret };
  }

  /** Deletes clients registered under any other public URL, with their grants and tokens: a new URL breaks their redirects. */
  pruneOtherIssuers(issuer: string): void {
    this.tx(() => this.db.prepare('DELETE FROM oauth_clients WHERE issuer != ?').run(issuer));
  }

  getClient(id: string): StoredClient | null {
    const row = this.db.prepare('SELECT * FROM oauth_clients WHERE id = ?').get(id) as unknown as ClientRow | undefined;
    return row ? toClient(row) : null;
  }

  /** True for 'none' when secret is null; secret methods need the matching secret. */
  checkClientSecret(id: string, secret: string | null): boolean {
    const row = this.db.prepare('SELECT secret_hash FROM oauth_clients WHERE id = ?').get(id) as unknown as
      Pick<ClientRow, 'secret_hash'> | undefined;
    if (!row) return false;
    if (row.secret_hash === null) return secret === null;
    return secret !== null && sameSecret(hex(secret), row.secret_hash);
  }

  /**
   * Server-side pending request, 600 s TTL. The id goes in the form; the CSRF token is checked with sameSecret.
   * At most 5 per client, oldest evicted: only the app that registered a client knows its id, so it can only churn its own.
   */
  saveRequest(req: AuthorizeRequest): { id: string; csrf: string } {
    const id = newSecret();
    const csrf = newSecret();
    const now = this.now();
    this.tx(() => {
      this.db.prepare('DELETE FROM oauth_requests WHERE expires_at <= ?').run(now);
      this.db.prepare('INSERT INTO oauth_requests (id_hash, csrf_hash, client_id, redirect_uri, code_challenge, resource, state, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(hex(id), hex(csrf), req.clientId, req.redirectUri, req.codeChallenge, req.resource, req.state, now + REQUEST_TTL_MS);
      // rowid follows insertion order among the rows that remain.
      this.db.prepare(`DELETE FROM oauth_requests WHERE client_id = ? AND rowid NOT IN
        (SELECT rowid FROM oauth_requests WHERE client_id = ? ORDER BY rowid DESC LIMIT ?)`).run(req.clientId, req.clientId, REQUESTS_PER_CLIENT);
    });
    return { id, csrf };
  }

  /** Single use: the second call with the same id returns null. Expired → null. A wrong CSRF token leaves the request in place. */
  takeRequest(id: string, csrf: string): AuthorizeRequest | null {
    return this.tx(() => {
      const row = this.db.prepare('SELECT * FROM oauth_requests WHERE id_hash = ?').get(hex(id)) as unknown as RequestRow | undefined;
      if (!row) return null;
      if (row.expires_at <= this.now()) {
        this.db.prepare('DELETE FROM oauth_requests WHERE id_hash = ?').run(row.id_hash);
        return null;
      }
      if (!sameSecret(hex(csrf), row.csrf_hash)) return null;
      this.db.prepare('DELETE FROM oauth_requests WHERE id_hash = ?').run(row.id_hash);
      return { clientId: row.client_id, redirectUri: row.redirect_uri, codeChallenge: row.code_challenge, resource: row.resource, state: row.state };
    });
  }

  /**
   * Marks the client approved and issues a 60 s code. 'full' when 20 other approved clients hold a live grant.
   * Throws if the client no longer exists (it may have been evicted while the request was pending).
   */
  approve(req: AuthorizeRequest): { ok: true; code: string } | { ok: false; error: 'full' } {
    const code = newSecret();
    const now = this.now();
    return this.tx(() => {
      if (!this.getClient(req.clientId)) throw new Error('Unknown OAuth client');
      this.pruneIdle(now, req.clientId);
      // Grants whose code expired unused never got tokens; drop them.
      this.db.prepare(`DELETE FROM oauth_grants WHERE NOT EXISTS (SELECT 1 FROM oauth_tokens WHERE grant_id = oauth_grants.id)
        AND NOT EXISTS (SELECT 1 FROM oauth_codes WHERE grant_id = oauth_grants.id AND expires_at > ?)`).run(now);
      // An approved app with no live grant can't call kordn, so it doesn't hold a place.
      const others = this.db.prepare(`SELECT COUNT(*) AS n FROM oauth_clients c WHERE approved_at IS NOT NULL AND id != ?
        AND EXISTS (SELECT 1 FROM oauth_grants WHERE client_id = c.id)`).get(req.clientId) as unknown as { n: number };
      if (others.n >= APPROVED_POOL) return { ok: false as const, error: 'full' as const };
      this.db.prepare('UPDATE oauth_clients SET approved_at = COALESCE(approved_at, ?) WHERE id = ?').run(now, req.clientId);
      const grantId = newSecret();
      this.db.prepare('INSERT INTO oauth_grants (id, client_id, resource, created_at) VALUES (?, ?, ?, ?)').run(grantId, req.clientId, req.resource, now);
      this.db.prepare('INSERT INTO oauth_codes (hash, grant_id, redirect_uri, code_challenge, expires_at) VALUES (?, ?, ?, ?, ?)')
        .run(hex(code), grantId, req.redirectUri, req.codeChallenge, now + CODE_TTL_MS);
      return { ok: true as const, code };
    });
  }

  /** Code + PKCE → tokens. Reusing a code revokes the grant it created. */
  exchangeCode(input: { code: string; clientId: string; redirectUri: string; verifier: string; resource: string }):
    { ok: true; tokens: IssuedTokens } | { ok: false; error: TokenError } {
    const fail = { ok: false as const, error: 'invalid_grant' as const };
    return this.tx(() => {
      const row = this.db.prepare(`SELECT c.hash, c.grant_id, c.redirect_uri, c.code_challenge, c.expires_at, c.used, g.client_id, g.resource
        FROM oauth_codes c JOIN oauth_grants g ON g.id = c.grant_id WHERE c.hash = ?`).get(hex(input.code)) as unknown as CodeRow | undefined;
      if (!row) return fail;
      if (row.used) {
        this.deleteGrant(row.grant_id);
        return fail;
      }
      if (row.expires_at <= this.now()) return fail;
      if (row.client_id !== input.clientId || row.redirect_uri !== input.redirectUri || row.resource !== input.resource) return fail;
      if (!verifyS256(input.verifier, row.code_challenge)) return fail;
      this.db.prepare('UPDATE oauth_codes SET used = 1 WHERE hash = ?').run(row.hash);
      return { ok: true as const, tokens: this.issue(row.grant_id) };
    });
  }

  /** Rotates. Presenting an already-rotated refresh token deletes the grant and returns its client as `reused`. */
  refresh(input: { refreshToken: string; clientId: string; resource: string }):
    { ok: true; tokens: IssuedTokens } | { ok: false; error: TokenError; reused?: StoredClient } {
    return this.tx(() => {
      const fail = { ok: false as const, error: 'invalid_grant' as const };
      const row = this.db.prepare(`SELECT t.hash, t.grant_id, t.rotated, g.client_id, g.resource, g.created_at, g.last_used_at
        FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE t.hash = ? AND t.kind = 'refresh'`)
        .get(hex(input.refreshToken)) as unknown as RefreshRow | undefined;
      // Replay of any rotated token kills the grant, whatever client or resource accompanies it.
      if (row?.rotated) {
        const owner = this.getClient(row.client_id);
        this.deleteGrant(row.grant_id);
        return owner ? { ...fail, reused: owner } : fail;
      }
      const client = this.getClient(input.clientId);
      if (!client) return { ok: false as const, error: 'invalid_client' as const };
      if (!row || row.client_id !== client.id || row.resource !== input.resource) return fail;
      const now = this.now();
      if (now - (row.last_used_at ?? row.created_at) > REFRESH_IDLE_MS) {
        this.deleteGrant(row.grant_id);
        return fail;
      }
      // Rotated refresh tokens stay until the grant goes, so any old replay is detected; drop spent access tokens.
      this.db.prepare("DELETE FROM oauth_tokens WHERE grant_id = ? AND kind = 'access' AND expires_at <= ?").run(row.grant_id, now);
      this.db.prepare('UPDATE oauth_tokens SET rotated = 1 WHERE hash = ?').run(row.hash);
      this.db.prepare('UPDATE oauth_grants SET last_used_at = ? WHERE id = ?').run(now, row.grant_id);
      return { ok: true as const, tokens: this.issue(row.grant_id) };
    });
  }

  /** Null for unknown, expired or revoked tokens. Updates last_used at most once per 60 s. */
  verifyAccess(token: string): AccessGrant | null {
    const now = this.now();
    const row = this.db.prepare(`SELECT t.expires_at, g.id, g.client_id, g.resource, g.last_used_at
      FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE t.hash = ? AND t.kind = 'access' AND t.expires_at > ?`)
      .get(hex(token), now) as unknown as AccessRow | undefined;
    if (!row) return null;
    if (row.last_used_at === null || now - row.last_used_at >= LAST_USED_INTERVAL_MS) {
      this.db.prepare('UPDATE oauth_grants SET last_used_at = ? WHERE id = ?').run(now, row.id);
    }
    return { clientId: row.client_id, resource: row.resource, expiresAt: Math.floor(row.expires_at / 1000) };
  }

  /** RFC 7009: revokes the grant behind an access or refresh token of this client. Unknown → no-op. */
  revokeToken(token: string, clientId: string): void {
    this.tx(() => {
      const row = this.db.prepare('SELECT g.id FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id WHERE t.hash = ? AND g.client_id = ?')
        .get(hex(token), clientId) as unknown as { id: string } | undefined;
      if (row) this.deleteGrant(row.id);
    });
  }

  /** Deletes the client, its grants, codes and tokens. Returns the deleted client or null. */
  revokeClient(clientId: string): StoredClient | null {
    return this.tx(() => {
      const client = this.getClient(clientId);
      if (!client) return null;
      this.db.prepare('DELETE FROM oauth_clients WHERE id = ?').run(clientId);
      return client;
    });
  }

  /** Approved clients, newest approval first. redirectHost is the host of the first redirect URI. */
  listApps(): ConnectedApp[] {
    const rows = this.db.prepare(`SELECT c.*, (SELECT MAX(last_used_at) FROM oauth_grants WHERE client_id = c.id) AS last_used_at
      FROM oauth_clients c WHERE c.approved_at IS NOT NULL ORDER BY c.approved_at DESC, c.rowid DESC`).all() as unknown as Array<ClientRow & { last_used_at: number | null }>;
    return rows.map((row) => {
      const client = toClient(row);
      return {
        clientId: client.id,
        name: client.name,
        redirectHost: new URL(client.redirectUris[0] as string).host,
        approvedAt: row.approved_at as number,
        lastUsedAt: row.last_used_at,
      };
    });
  }

  private issue(grantId: string): IssuedTokens {
    const accessToken = newSecret();
    const refreshToken = newSecret();
    const insert = this.db.prepare('INSERT INTO oauth_tokens (hash, grant_id, kind, expires_at) VALUES (?, ?, ?, ?)');
    insert.run(hex(accessToken), grantId, 'access', this.now() + ACCESS_TTL_S * 1000);
    insert.run(hex(refreshToken), grantId, 'refresh', null);
    return { accessToken, refreshToken, expiresIn: ACCESS_TTL_S };
  }

  private deleteGrant(grantId: string): void {
    this.db.prepare('DELETE FROM oauth_grants WHERE id = ?').run(grantId);
  }

  /**
   * Approved clients whose last activity (approval, or a grant's last use) is over 30 days old, then grants idle
   * that long: refresh() would refuse them anyway. After this every remaining grant is live. Runs inside a transaction.
   */
  private pruneIdle(now: number, keepClientId: string | null = null): void {
    const cutoff = now - REFRESH_IDLE_MS;
    this.db.prepare(`DELETE FROM oauth_clients WHERE approved_at IS NOT NULL AND id IS NOT ? AND MAX(approved_at,
      COALESCE((SELECT MAX(COALESCE(last_used_at, created_at)) FROM oauth_grants WHERE client_id = oauth_clients.id), 0)) < ?`)
      .run(keepClientId, cutoff);
    this.db.prepare('DELETE FROM oauth_grants WHERE COALESCE(last_used_at, created_at) < ?').run(cutoff);
  }

  private tx<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const result = fn();
      this.db.exec('COMMIT');
      return result;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  close(): void {
    this.db.close();
  }
}

function toClient(row: ClientRow): StoredClient {
  return {
    id: row.id,
    name: row.name,
    redirectUris: JSON.parse(row.redirect_uris) as string[],
    authMethod: row.auth_method,
    createdAt: row.created_at,
    approvedAt: row.approved_at,
  };
}
