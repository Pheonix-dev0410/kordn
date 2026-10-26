import { afterEach, describe, expect, it } from 'vitest';
import { harness, transfer } from './helpers.js';
import { Ledger } from '../src/ledger.js';
import { join } from 'node:path';

let h: ReturnType<typeof harness>;
afterEach(() => h?.close());

describe('append-only audit chain', () => {
  it('validates every entry and blocks updates and deletes', () => {
    h = harness();
    h.ledger.admit(h.policy.agentId, transfer());
    expect(h.ledger.audit.verifyChain()).toBe(true);
    expect(() => h.ledger.db.exec("UPDATE audit_events SET event_hash='corrupt'")).toThrow('append-only');
    expect(() => h.ledger.db.exec('DELETE FROM audit_events')).toThrow('append-only');
    expect(() => h.ledger.db.exec("INSERT OR REPLACE INTO audit_events VALUES (1, '{}', 'corrupt')")).toThrow('append-only');
    expect(() => h.ledger.transaction(() => h.ledger.event(h.policy.agentId, 'policy.allowed', null, null, null, null, null, { apiToken: 'sensitive' }))).toThrow('unsafe audit metadata');
    expect(() => h.ledger.transaction(() => h.ledger.event(h.policy.agentId, 'bad' as never))).toThrow();
  });

  it.each(['edit', 'delete-middle', 'delete-tail', 'reorder'])('detects %s even when protection triggers are bypassed', (attack) => {
    h = harness();
    h.ledger.admit(h.policy.agentId, transfer());
    h.ledger.db.exec('DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete');
    const rows = h.ledger.db.prepare('SELECT * FROM audit_events ORDER BY seq').all();
    if (attack === 'edit') h.ledger.db.prepare('UPDATE audit_events SET event_json=? WHERE seq=2').run('{}');
    if (attack === 'delete-middle') h.ledger.db.exec('DELETE FROM audit_events WHERE seq=2');
    if (attack === 'delete-tail') h.ledger.db.exec('DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events)');
    if (attack === 'reorder') {
      h.ledger.db.prepare('UPDATE audit_events SET event_json=?,event_hash=? WHERE seq=1').run(String(rows[1]!.event_json), String(rows[1]!.event_hash));
      h.ledger.db.prepare('UPDATE audit_events SET event_json=?,event_hash=? WHERE seq=2').run(String(rows[0]!.event_json), String(rows[0]!.event_hash));
    }
    expect(h.ledger.audit.verifyChain()).toBe(false);
    expect(() => new Ledger(join(h.dir, 'ledger.sqlite'), h.clock)).toThrow('audit chain is invalid');
    if (attack === 'delete-tail') expect(() => h.ledger.admit(h.policy.agentId, transfer(1))).toThrow('checkpoint');
  });
});
