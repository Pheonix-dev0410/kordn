import { randomBytes, randomUUID } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { openPrivateDatabase } from './database.js';
import { AuditLog } from './audit.js';
import { requestHash } from './hash.js';
import { evaluate } from './policy.js';
import { APPROVAL_TTL_SEC, AuditEvent, BUDGET_STATES, canTransition, Policy } from './schema.js';
import type { Clock, DenyCode, State, ToolCall, TransferCall, TransferReasonCode, Usage } from './schema.js';
import type { ApprovalError } from './guardian-api.js';

export class GuardianError extends Error {
  constructor(readonly code: DenyCode, message: string = code) { super(message); }
}

export class ApprovalDecisionError extends Error {
  constructor(readonly code: ApprovalError) { super(code); }
}

export class PolicyVersionConflict extends Error {}

export interface Reservation {
  id: string;
  agentId: string;
  call: TransferCall;
  requestHash: string;
  state: State;
  policyVersion: number;
  createdMs: number;
  updatedMs: number;
  expiresMs: number;
  digest: string;
  nonce: string | null;
  reasonCode: TransferReasonCode | null;
}

type Admission = { kind: 'read' } | { kind: 'transfer'; reservation: Reservation; fresh: boolean };
type PolicyRecord = { policy: Policy; version: number; revoked: boolean };

export class Ledger {
  readonly db: DatabaseSync;
  readonly audit: AuditLog;

  constructor(path: string, readonly clock: Clock = { nowMs: Date.now }, readonly approvalTtlMs = APPROVAL_TTL_SEC * 1000) {
    if (!Number.isSafeInteger(approvalTtlMs) || approvalTtlMs <= 0) throw new Error('invalid approval TTL');
    this.db = openPrivateDatabase(path);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS policies (
        agent_id TEXT PRIMARY KEY, version INTEGER NOT NULL, policy_json TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
      );
      CREATE TABLE IF NOT EXISTS reservations (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, call_json TEXT NOT NULL,
        idempotency_key TEXT NOT NULL, request_hash TEXT NOT NULL,
        state TEXT NOT NULL, policy_version INTEGER NOT NULL,
        created_ms INTEGER NOT NULL, updated_ms INTEGER NOT NULL,
        expires_ms INTEGER NOT NULL, digest TEXT NOT NULL, nonce TEXT,
        reason_code TEXT, amount_minor INTEGER NOT NULL,
        UNIQUE(agent_id, idempotency_key)
      );
      CREATE INDEX IF NOT EXISTS reservations_window ON reservations(agent_id, created_ms, state);
      CREATE INDEX IF NOT EXISTS reservations_state ON reservations(agent_id, state, expires_ms);
      CREATE TABLE IF NOT EXISTS usage_events (
        id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, created_ms INTEGER NOT NULL, tool TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS reads_window ON usage_events(agent_id, created_ms);
    `);
    this.audit = new AuditLog(this.db);
    if (!this.audit.verifyChain()) { this.db.close(); throw new Error('audit chain is invalid'); }
  }

  transaction<T>(fn: () => T): T {
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

  getPolicy(agentId: string): PolicyRecord {
    const row = this.db.prepare('SELECT * FROM policies WHERE agent_id = ?').get(agentId);
    if (!row) throw new GuardianError('INVALID_ARGUMENTS');
    return { policy: Policy.parse(JSON.parse(String(row.policy_json))), version: Number(row.version), revoked: Boolean(row.revoked) };
  }

  /** expectedVersion=0 creates a policy; updates never clear revocation. */
  updatePolicy(input: Policy, expectedVersion: number): PolicyRecord {
    const policy = Policy.parse(input);
    return this.transaction(() => {
      const previous = this.db.prepare('SELECT * FROM policies WHERE agent_id = ?').get(policy.agentId);
      if ((previous ? Number(previous.version) : 0) !== expectedVersion) throw new PolicyVersionConflict('stale policy version');
      const version = expectedVersion + 1;
      this.db.prepare(`INSERT INTO policies VALUES (?, ?, ?, 0) ON CONFLICT(agent_id)
        DO UPDATE SET version=excluded.version, policy_json=excluded.policy_json`).run(policy.agentId, version, JSON.stringify(policy));
      this.event(policy.agentId, 'policy.updated', null, null, version, null, null, {
        oldHash: previous ? requestHash(JSON.parse(String(previous.policy_json))) : null, newHash: requestHash(policy),
      });
      return this.getPolicy(policy.agentId);
    });
  }

  /** What counts against the agent's limits right now. */
  currentUsage(agentId: string): Usage {
    return this.usage(agentId, this.getPolicy(agentId).policy, this.clock.nowMs());
  }

  private usage(agentId: string, policy: Policy, nowMs: number, excludeId?: string): Usage {
    const reads = this.db.prepare("SELECT COUNT(*) AS count FROM usage_events WHERE agent_id=? AND created_ms>? AND tool!='af_get_transfer_status'")
      .get(agentId, nowMs - policy.reads.windowSec * 1000)!;
    const marks = BUDGET_STATES.map(() => '?').join(',');
    // Unresolved actions keep quota even after their original window has elapsed.
    const transfers = this.db.prepare(`SELECT COUNT(*) AS count, COALESCE(SUM(amount_minor),0) AS total
      FROM reservations WHERE agent_id=? AND state IN (${marks}) AND (state!='SUCCEEDED' OR MAX(created_ms, updated_ms)>?)
        AND (? IS NULL OR id!=?)`).get(agentId, ...BUDGET_STATES,
        nowMs - policy.transfers.windowSec * 1000, excludeId ?? null, excludeId ?? null)!;
    return { reads: Number(reads.count), transfers: Number(transfers.count), transferredMinor: Number(transfers.total) };
  }

  admit(agentId: string, call: ToolCall): Admission {
    const result = this.transaction((): Admission | GuardianError => {
      const { policy, version, revoked } = this.getPolicy(agentId);
      const nowMs = this.clock.nowMs();
      const hash = requestHash(call);
      this.event(agentId, 'action.attempted', call, hash, version);
      if (revoked) return this.denied(agentId, call, hash, version, 'SESSION_REVOKED');
      if (call.tool === 'af_propose_transfer') {
        const row = this.db.prepare('SELECT * FROM reservations WHERE agent_id=? AND idempotency_key=?')
          .get(agentId, call.idempotencyKey);
        if (row) {
          if (row.request_hash !== hash) return this.denied(agentId, call, hash, version, 'IDEMPOTENCY_CONFLICT');
          this.event(agentId, 'policy.allowed', call, hash, version, null, String(row.id), { duplicate: true });
          return { kind: 'transfer', reservation: this.decode(row), fresh: false };
        }
      }
      if (call.tool === 'af_get_transfer_status') {
        const owned = this.get(call.transferRef, agentId);
        if (!owned || owned.call.resourceId !== policy.resourceId) return this.denied(agentId, call, hash, version, 'INVALID_ARGUMENTS');
        const polls = this.db.prepare("SELECT COUNT(*) AS count FROM usage_events WHERE agent_id=? AND created_ms>? AND tool='af_get_transfer_status'")
          .get(agentId, nowMs - 60_000)!;
        if (Number(polls.count) >= 60) return this.denied(agentId, call, hash, version, 'RATE_LIMITED');
      }
      const verdict = evaluate({ agentId, call, policy, revoked, usage: this.usage(agentId, policy, nowMs), nowMs });
      if (verdict.kind === 'deny') return this.denied(agentId, call, hash, version, verdict.code);
      if (call.tool !== 'af_propose_transfer') {
        this.db.prepare('INSERT INTO usage_events VALUES (?, ?, ?, ?)').run(randomUUID(), agentId, nowMs, call.tool);
        this.event(agentId, 'policy.allowed', call, hash, version);
        return { kind: 'read' };
      }
      const id = `tr_${randomUUID().replaceAll('-', '')}`;
      const expiresMs = nowMs + this.approvalTtlMs;
      const digest = hash;
      const nonce = randomBytes(32).toString('hex');
      this.db.prepare(`INSERT INTO reservations VALUES (?, ?, ?, ?, ?, 'RESERVED', ?, ?, ?, ?, ?, ?, NULL, ?)`)
        .run(id, agentId, JSON.stringify(call), call.idempotencyKey, hash, version, nowMs, nowMs, expiresMs, digest, nonce, call.amountMinor);
      if (verdict.kind === 'allow') this.event(agentId, 'policy.allowed', call, hash, version, null, id);
      if (verdict.kind === 'require_approval') this.transitionInTransaction(id, 'PENDING_APPROVAL');
      return { kind: 'transfer', reservation: this.get(id)!, fresh: true };
    });
    if (result instanceof GuardianError) throw result;
    return result;
  }

  private denied(agentId: string, call: ToolCall | null, hash: string | null, version: number | null, code: DenyCode,
    extra: AuditEvent['metadata'] = {}): GuardianError {
    // Payee and amount of a refused transfer, so the owner sees what was attempted. Both are schema-checked.
    const metadata: AuditEvent['metadata'] = call?.tool === 'af_propose_transfer' ? { payeeId: call.payeeId, amountMinor: call.amountMinor, ...extra } : { ...extra };
    this.event(agentId, 'policy.denied', call, hash, version, code, null, metadata);
    return new GuardianError(code);
  }

  /** A refusal outside admit(): a malformed call, a stopped agent, or a bank that failed (with why, in `metadata`). */
  recordDenied(agentId: string, code: DenyCode, call: ToolCall | null = null, metadata: AuditEvent['metadata'] = {}): void {
    this.transaction(() => {
      this.event(agentId, 'action.attempted', call);
      this.denied(agentId, call, null, null, code, metadata);
    });
  }

  event(agentId: string, event: AuditEvent['event'], call: ToolCall | null = null, hash: string | null = null,
    version: number | null = null, reasonCode: DenyCode | null = null, reservationId: string | null = null,
    metadata: AuditEvent['metadata'] = {}): void {
    this.audit.append({ timestamp: new Date(this.clock.nowMs()).toISOString(), event, agent: agentId,
      tool: call?.tool ?? null, requestHash: hash, policyVersion: version, reasonCode, reservationId, metadata });
  }

  private decode(row: Record<string, unknown>): Reservation {
    return { id: String(row.id), agentId: String(row.agent_id), call: JSON.parse(String(row.call_json)),
      requestHash: String(row.request_hash), state: row.state as State, policyVersion: Number(row.policy_version),
      createdMs: Number(row.created_ms), updatedMs: Number(row.updated_ms), expiresMs: Number(row.expires_ms),
      digest: String(row.digest), nonce: row.nonce === null ? null : String(row.nonce), reasonCode: row.reason_code as TransferReasonCode | null };
  }

  get(id: string, agentId?: string): Reservation | null {
    const row = this.db.prepare('SELECT * FROM reservations WHERE id=? AND (? IS NULL OR agent_id=?)')
      .get(id, agentId ?? null, agentId ?? null);
    return row ? this.decode(row) : null;
  }

  list(agentId?: string): Reservation[] {
    return this.db.prepare('SELECT * FROM reservations WHERE (? IS NULL OR agent_id=?) ORDER BY created_ms, id')
      .all(agentId ?? null, agentId ?? null).map((row) => this.decode(row));
  }

  listByState(agentId: string, states: readonly State[], expiresBeforeMs?: number): Reservation[] {
    if (states.length === 0) return [];
    const expiry = expiresBeforeMs === undefined ? '' : ' AND expires_ms<=?';
    return this.db.prepare(`SELECT * FROM reservations WHERE agent_id=? AND state IN (${states.map(() => '?').join(',')})
      ${expiry} ORDER BY created_ms, id`)
      .all(agentId, ...states, ...(expiresBeforeMs === undefined ? [] : [expiresBeforeMs])).map((row) => this.decode(row));
  }

  private transitionInTransaction(id: string, state: State, reason: TransferReasonCode | null = null,
    event?: AuditEvent['event'], metadata: AuditEvent['metadata'] = {}): Reservation {
    const r = this.get(id);
    if (!r || !canTransition(r.state, state)) throw new GuardianError('INVALID_ARGUMENTS', 'invalid state transition');
    this.db.prepare('UPDATE reservations SET state=?, updated_ms=?, reason_code=?, nonce=NULL WHERE id=?')
      .run(state, this.clock.nowMs(), reason, id);
    const events: Partial<Record<State, AuditEvent['event']>> = {
      PENDING_APPROVAL: 'policy.require_approval', APPROVED: 'approval.granted', REJECTED: 'approval.rejected',
      EXPIRED: 'approval.expired', DISPATCHING: 'transfer.dispatching', SUCCEEDED: 'transfer.succeeded',
      FAILED: 'transfer.failed', UNKNOWN: 'transfer.unknown',
    };
    // The pending nonce remains private to the admin API until consumed.
    if (state === 'PENDING_APPROVAL') this.db.prepare('UPDATE reservations SET nonce=? WHERE id=?').run(r.nonce, id);
    this.event(r.agentId, event ?? events[state]!, r.call, r.requestHash, r.policyVersion,
      reason === 'ADAPTER_FAILED' ? null : reason, id, { ...metadata, state });
    return this.get(id)!;
  }

  transition(id: string, state: State, reason: TransferReasonCode | null = null, event?: AuditEvent['event'],
    metadata: AuditEvent['metadata'] = {}): Reservation {
    return this.transaction(() => this.transitionInTransaction(id, state, reason, event, metadata));
  }

  /** Re-check under the same writer lock that commits DISPATCHING. */
  dispatch(id: string): Reservation {
    const result = this.transaction(() => {
      const r = this.get(id);
      if (!r || !['RESERVED', 'APPROVED'].includes(r.state)) throw new GuardianError('INVALID_ARGUMENTS');
      const { policy, version, revoked } = this.getPolicy(r.agentId);
      const verdict = evaluate({ agentId: r.agentId, call: r.call, policy, revoked,
        usage: this.usage(r.agentId, policy, this.clock.nowMs(), id), nowMs: this.clock.nowMs() });
      if (verdict.kind === 'deny' || version !== r.policyVersion ||
          (verdict.kind === 'require_approval' && r.state !== 'APPROVED')) {
        const code = verdict.kind === 'deny' ? verdict.code : 'INVALID_ARGUMENTS';
        this.transitionInTransaction(id, 'REJECTED', code);
        return this.denied(r.agentId, r.call, r.requestHash, version, code);
      }
      return this.transitionInTransaction(id, 'DISPATCHING');
    });
    if (result instanceof GuardianError) throw result;
    return result;
  }

  decide(id: string, nonce: string, digest: string | null, approve: boolean, agentId: string): Reservation {
    const result = this.transaction(() => {
      const r = this.get(id, agentId);
      if (!r || r.state !== 'PENDING_APPROVAL') {
        this.denied(agentId, null, null, null, 'INVALID_ARGUMENTS');
        return new ApprovalDecisionError(r?.state === 'EXPIRED' ? 'APPROVAL_EXPIRED' : 'NOT_PENDING');
      }
      if (r.expiresMs <= this.clock.nowMs()) {
        this.transitionInTransaction(id, 'EXPIRED', 'APPROVAL_EXPIRED');
        return new ApprovalDecisionError('APPROVAL_EXPIRED');
      }
      if (r.nonce !== nonce || (approve && r.requestHash !== digest)) {
        this.denied(agentId, null, null, null, 'INVALID_ARGUMENTS');
        return new ApprovalDecisionError(r.nonce !== nonce ? 'BAD_NONCE' : 'STALE_DIGEST');
      }
      const { policy, version, revoked } = this.getPolicy(agentId);
      const verdict = evaluate({ agentId, call: r.call, policy, revoked,
        usage: this.usage(agentId, policy, this.clock.nowMs(), id), nowMs: this.clock.nowMs() });
      if (approve && (verdict.kind === 'deny' || version !== r.policyVersion)) {
        const code = verdict.kind === 'deny' ? verdict.code : 'INVALID_ARGUMENTS';
        this.transitionInTransaction(id, 'REJECTED', code);
        return new GuardianError(code);
      }
      return this.transitionInTransaction(id, approve ? 'APPROVED' : 'REJECTED');
    });
    if (result instanceof GuardianError || result instanceof ApprovalDecisionError) throw result;
    return result;
  }

  revoke(agentId: string): void {
    this.transaction(() => {
      this.getPolicy(agentId);
      this.db.prepare('UPDATE policies SET revoked=1 WHERE agent_id=?').run(agentId);
      for (const r of this.listByState(agentId, ['RESERVED', 'PENDING_APPROVAL', 'APPROVED'])) {
        this.transitionInTransaction(r.id, 'REJECTED', 'SESSION_REVOKED');
      }
      this.event(agentId, 'session.revoked');
    });
  }

  close(): void { this.db.close(); }
}
