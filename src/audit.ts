import type { DatabaseSync } from 'node:sqlite';
import { AuditEvent } from './schema.js';
import { canonicalJson, sha256 } from './hash.js';

export class AuditLog {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`
      CREATE TABLE IF NOT EXISTS audit_events (
        seq INTEGER PRIMARY KEY, event_json TEXT NOT NULL, event_hash TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_head (id INTEGER PRIMARY KEY CHECK(id=1), seq INTEGER NOT NULL, hash TEXT);
      INSERT OR IGNORE INTO audit_head VALUES (1, 0, NULL);
      CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_events
        BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
      CREATE TRIGGER IF NOT EXISTS audit_no_replace BEFORE INSERT ON audit_events
        WHEN EXISTS (SELECT 1 FROM audit_events WHERE seq=NEW.seq)
        BEGIN SELECT RAISE(ABORT, 'audit is append-only'); END;
    `);
  }

  /** Caller owns the transaction so financial state and evidence commit together. */
  append(input: Omit<AuditEvent, 'prevHash'>): void {
    for (const [key, value] of Object.entries(input.metadata)) {
      if (/secret|token|password|prompt|authorization|cookie|memo|description/i.test(key) ||
          (typeof value === 'string' && value.length > 256)) throw new Error('unsafe audit metadata');
    }
    const last = this.db.prepare('SELECT seq, event_hash FROM audit_events ORDER BY seq DESC LIMIT 1').get();
    const head = this.db.prepare('SELECT seq, hash FROM audit_head WHERE id=1').get();
    if (!head || Number(head.seq) !== Number(last?.seq ?? 0) || head.hash !== (last?.event_hash ?? null)) {
      throw new Error('audit tail does not match checkpoint');
    }
    const seq = last ? Number(last.seq) + 1 : 1;
    const event = AuditEvent.parse({ ...input, prevHash: last?.event_hash ?? null });
    const json = canonicalJson(event);
    const hash = sha256(canonicalJson({ seq, event }));
    this.db.prepare('INSERT INTO audit_events VALUES (?, ?, ?)').run(seq, json, hash);
    this.db.prepare('UPDATE audit_head SET seq=?, hash=? WHERE id=1').run(seq, hash);
  }

  verifyChain(): boolean {
    let prevHash: string | null = null;
    let seq = 1;
    try {
      for (const row of this.db.prepare('SELECT * FROM audit_events ORDER BY seq').all()) {
        const event = AuditEvent.parse(JSON.parse(String(row.event_json)));
        if (Number(row.seq) !== seq || event.prevHash !== prevHash ||
            sha256(canonicalJson({ seq, event })) !== row.event_hash) return false;
        prevHash = String(row.event_hash);
        seq++;
      }
      const head = this.db.prepare('SELECT seq, hash FROM audit_head WHERE id=1').get();
      return !!head && Number(head.seq) === seq - 1 && head.hash === prevHash;
    } catch { return false; }
  }

  list(filter: { agentId?: string; events?: AuditEvent['event'][]; limit?: number } = {}): AuditEvent[] {
    const limit = Math.min(1000, Math.max(1, filter.limit ?? 100));
    if (filter.events?.length === 0) return [];
    const events = filter.events ? ` AND json_extract(event_json, '$.event') IN (${filter.events.map(() => '?').join(',')})` : '';
    return this.db.prepare(`SELECT event_json FROM audit_events
      WHERE (? IS NULL OR json_extract(event_json, '$.agent') = ?)
      ${events} ORDER BY seq DESC LIMIT ?`).all(filter.agentId ?? null, filter.agentId ?? null,
        ...(filter.events ?? []), limit).map((r) => AuditEvent.parse(JSON.parse(String(r.event_json))));
  }
}
