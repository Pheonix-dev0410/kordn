import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { secret as newSecret, sameSecret } from '../admin/session.js';
import { openPrivateDatabase } from '../database.js';
import type { AuthMethod, ClientRegistration } from './client-metadata.js';

const UNAPPROVED_POOL = 50;
const UNAPPROVED_TTL_MS = 3600_000;

export interface StoredClient {
  id: string;
  name: string;
  redirectUris: string[];
  authMethod: AuthMethod;
  createdAt: number;
  approvedAt: number | null;
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
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS oauth_clients (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        redirect_uris TEXT NOT NULL,
        auth_method TEXT NOT NULL,
        secret_hash TEXT,
        created_at INTEGER NOT NULL,
        approved_at INTEGER
      );`);
  }

  static open(path: string, now?: () => number): OAuthStore {
    return new OAuthStore(openPrivateDatabase(path), now);
  }

  /** Prunes and evicts unapproved clients as needed. The secret is returned only here, and only for secret auth methods. */
  registerClient(reg: ClientRegistration): { client: StoredClient; secret: string | null } {
    const id = newSecret();
    const secret = reg.authMethod === 'none' ? null : newSecret();
    const createdAt = this.now();
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db.prepare('DELETE FROM oauth_clients WHERE approved_at IS NULL AND created_at < ?').run(createdAt - UNAPPROVED_TTL_MS);
      this.db.prepare('INSERT INTO oauth_clients (id, name, redirect_uris, auth_method, secret_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(id, reg.name, JSON.stringify(reg.redirectUris), reg.authMethod, secret === null ? null : hex(secret), createdAt);
      this.db.prepare(`DELETE FROM oauth_clients WHERE approved_at IS NULL AND id IN (
        SELECT id FROM oauth_clients WHERE approved_at IS NULL ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET ?)`)
        .run(UNAPPROVED_POOL);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return { client: { id, name: reg.name, redirectUris: [...reg.redirectUris], authMethod: reg.authMethod, createdAt, approvedAt: null }, secret };
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
