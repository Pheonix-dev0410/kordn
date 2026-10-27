import { randomBytes } from 'node:crypto';
import type {
  ActivityFilter,
  ApprovalResult,
  CallResult,
  Guardian,
  Overview,
  PendingApproval,
  PolicyUpdateResult,
  TransferSummary,
} from '../src/guardian-api.js';
import { cleanAppText } from '../src/guardian.js';
import { requestHash } from '../src/hash.js';
import { CHECKING_ACCOUNT, FIXTURE_EPOCH_MS, TRANSACTIONS, transactionDate } from '../src/mock-bank.js';
import {
  APPROVAL_TTL_SEC,
  type AuditEvent,
  type DenyCode,
  parseToolCall,
  Policy,
  type State,
  ToolName,
  type TransferCall,
  type TransferReasonCode,
} from '../src/schema.js';

// In-memory stand-in for the guardian (#6) so the MCP server and admin UI can be built
// and tested before it lands. Enforces the per-call rules (agent, resource, allow flags,
// payee, single limit, lookback, approval threshold) and idempotency keys. No ledger, no
// rolling limits, no persistence. Not a security boundary.
//
// Transfers jump straight from RESERVED or PENDING_APPROVAL to SUCCEEDED: there is no
// executor, so a UI built on this never sees APPROVED or DISPATCHING. The real one does.

const DEFAULT_ACTIVITY_LIMIT = 100;
const MAX_ACTIVITY_LIMIT = 1000;

// What af_propose_transfer reports for each state, e.g. on an idempotent retry. In-progress
// states report unknown: the outcome isn't known yet.
const PROPOSE_STATE = {
  RESERVED: 'unknown',
  PENDING_APPROVAL: 'pending_approval',
  APPROVED: 'unknown',
  DISPATCHING: 'unknown',
  UNKNOWN: 'unknown',
  SUCCEEDED: 'succeeded',
  FAILED: 'failed',
  REJECTED: 'rejected',
  EXPIRED: 'expired',
} as const satisfies Record<State, string>;

interface Transfer {
  ref: string;
  agentId: string;
  call: TransferCall;
  hash: string;
  state: State;
  reasonCode: TransferReasonCode | null;
  createdAt: string;
  updatedAt: string;
  pending?: PendingApproval;
}

export interface FakeGuardianOptions {
  policy: Policy;
  nowMs?: () => number;
}

export function createFakeGuardian(options: FakeGuardianOptions): Guardian {
  const now = options.nowMs ?? (() => Date.now());
  let policy = Policy.parse(options.policy);
  let version = 1;
  const revoked = new Set<string>();
  const transfers = new Map<string, Transfer>();
  // An idempotency key is scoped to (agent, key). Only reserved transfers are
  // recorded, so a denied request can be retried once the policy allows it.
  const byIdempotencyKey = new Map<string, Transfer>();
  const activity: AuditEvent[] = [];

  const iso = () => new Date(now()).toISOString();
  const token = (bytes: number) => randomBytes(bytes).toString('base64url');

  function log(event: AuditEvent['event'], agent: string, fields: Partial<AuditEvent> = {}): void {
    activity.push({
      timestamp: iso(),
      event,
      agent,
      tool: null,
      requestHash: null,
      policyVersion: version,
      reasonCode: null,
      reservationId: null,
      metadata: {},
      prevHash: null,
      ...fields,
    });
  }

  function deny(agentId: string, tool: AuditEvent['tool'], code: DenyCode, hash: string | null = null, call?: TransferCall): CallResult {
    const metadata = call ? { payeeId: call.payeeId, amountMinor: call.amountMinor } : {};
    log('policy.denied', agentId, { tool, reasonCode: code, requestHash: hash, metadata });
    return { ok: false, error: { code, message: code } };
  }

  function expire(t: Transfer): void {
    if (t.state === 'PENDING_APPROVAL' && t.pending && Date.parse(t.pending.expiresAt) <= now()) {
      t.state = 'EXPIRED';
      t.reasonCode = 'APPROVAL_EXPIRED';
      t.updatedAt = iso();
      log('approval.expired', t.agentId, { tool: 'af_propose_transfer', reservationId: t.ref });
    }
  }

  /** The hard rules, against the current policy. Proposal and approval both use it. */
  function checkTransfer(call: TransferCall): DenyCode | null {
    const rules = policy.transfers;
    if (call.resourceId !== policy.resourceId) return 'UNKNOWN_ACTION';
    if (!rules.allow) return 'CAPABILITY_DISABLED';
    if (!rules.allowedPayeeIds.includes(call.payeeId)) return 'UNAPPROVED_PAYEE';
    if (call.amountMinor > rules.maxSingleMinor) return 'SINGLE_LIMIT';
    return null;
  }

  /** What af_propose_transfer reports for a transfer, now. */
  function proposeResult(t: Transfer): CallResult {
    expire(t);
    const state = PROPOSE_STATE[t.state];
    return { ok: true, result: { state, transferRef: t.ref, reasonCode: t.reasonCode } };
  }

  function proposeTransfer(agentId: string, call: TransferCall): CallResult {
    const hash = requestHash(call);
    const key = `${agentId}\n${call.idempotencyKey}`;
    const existing = byIdempotencyKey.get(key);
    if (existing) {
      // A retry never reserves or executes again; it reports the original transfer.
      if (existing.hash !== hash) return deny(agentId, call.tool, 'IDEMPOTENCY_CONFLICT', hash, call);
      return proposeResult(existing);
    }

    const rules = policy.transfers;
    const code = checkTransfer(call);
    if (code) return deny(agentId, call.tool, code, hash, call);

    const ref = `tr_${token(16)}`;
    const t: Transfer = { ref, agentId, call, hash, state: 'RESERVED', reasonCode: null, createdAt: iso(), updatedAt: iso() };
    transfers.set(ref, t);
    byIdempotencyKey.set(key, t);

    if (call.amountMinor > rules.humanApprovalAboveMinor) {
      t.state = 'PENDING_APPROVAL';
      t.pending = {
        reservationId: ref,
        agentId,
        resourceId: call.resourceId,
        payeeId: call.payeeId,
        amountMinor: call.amountMinor,
        currency: call.currency,
        policyVersion: version,
        digest: hash,
        nonce: token(16),
        expiresAt: new Date(now() + APPROVAL_TTL_SEC * 1000).toISOString(),
      };
      log('policy.require_approval', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
      return proposeResult(t);
    }

    t.state = 'SUCCEEDED';
    log('policy.allowed', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
    log('transfer.succeeded', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
    return proposeResult(t);
  }

  function settle(reservationId: string, nonce: string, digest: string | null): ApprovalResult {
    const t = transfers.get(reservationId);
    if (t) expire(t);
    if (!t?.pending || t.state !== 'PENDING_APPROVAL') return { ok: false, code: t?.state === 'EXPIRED' ? 'APPROVAL_EXPIRED' : 'NOT_PENDING' };
    // The nonce is one-use because a settled transfer is no longer PENDING_APPROVAL.
    if (nonce !== t.pending.nonce) return { ok: false, code: 'BAD_NONCE' };
    if (digest !== null && digest !== t.pending.digest) return { ok: false, code: 'STALE_DIGEST' };
    if (digest === null) {
      t.state = 'REJECTED';
      t.updatedAt = iso();
      log('approval.rejected', t.agentId, { tool: 'af_propose_transfer', reservationId });
      return { ok: true };
    }
    // Approval can't override a hard deny: re-check against the current policy.
    const code = revoked.has(t.agentId) ? 'SESSION_REVOKED' : checkTransfer(t.call);
    if (code) {
      t.state = 'REJECTED';
      t.reasonCode = code;
      t.updatedAt = iso();
      log('approval.rejected', t.agentId, { tool: 'af_propose_transfer', reservationId, reasonCode: code });
      return { ok: false, code };
    }
    t.state = 'SUCCEEDED';
    t.updatedAt = iso();
    log('approval.granted', t.agentId, { tool: 'af_propose_transfer', reservationId });
    log('transfer.succeeded', t.agentId, { tool: 'af_propose_transfer', reservationId });
    return { ok: true };
  }

  function handle(agentId: string, tool: unknown, args: unknown): CallResult {
    const name = ToolName.safeParse(tool);
    const toolName = name.success ? name.data : null;
    // One guardian serves one agent. Anyone else is unknown, never governed by this policy.
    // Logged under our own agent so the event stays a valid AuditEvent; the caller's id is
    // kept, truncated, as data.
    if (agentId !== policy.agentId) {
      log('policy.denied', policy.agentId, {
        tool: toolName,
        reasonCode: 'UNKNOWN_ACTION',
        metadata: { unknownAgent: String(agentId).slice(0, 64) },
      });
      return { ok: false, error: { code: 'UNKNOWN_ACTION', message: 'UNKNOWN_ACTION' } };
    }
    if (revoked.has(agentId)) return deny(agentId, toolName, 'SESSION_REVOKED');
    if (!toolName) {
      log('action.attempted', agentId, { metadata: { tool: typeof tool === 'string' ? tool.slice(0, 64) : null } });
      return deny(agentId, null, 'UNKNOWN_ACTION');
    }
    const call = parseToolCall(toolName, args);
    if (!call) return deny(agentId, toolName, 'INVALID_ARGUMENTS');
    log('action.attempted', agentId, { tool: call.tool, requestHash: requestHash(call) });

    switch (call.tool) {
      case 'af_get_balance':
        if (call.resourceId !== policy.resourceId) return deny(agentId, call.tool, 'UNKNOWN_ACTION');
        if (!policy.reads.allow) return deny(agentId, call.tool, 'CAPABILITY_DISABLED');
        log('read.executed', agentId, { tool: call.tool });
        return {
          ok: true,
          result: { currency: 'USD', balanceMinor: CHECKING_ACCOUNT.openingBalanceMinor, observedAt: iso() },
        };
      case 'af_list_transactions': {
        if (call.resourceId !== policy.resourceId) return deny(agentId, call.tool, 'UNKNOWN_ACTION');
        if (!policy.reads.allow) return deny(agentId, call.tool, 'CAPABILITY_DISABLED');
        // Denied rather than clamped, like any other out-of-policy argument. Measured from the
        // mock bank's "today" (the fixture epoch), which its transaction dates are relative to.
        const oldest = new Date(FIXTURE_EPOCH_MS - policy.reads.maxLookbackDays * 86_400_000).toISOString().slice(0, 10);
        if (call.fromDate < oldest) return deny(agentId, call.tool, 'INVALID_ARGUMENTS');
        const transactions = TRANSACTIONS.filter((tx) => transactionDate(tx, FIXTURE_EPOCH_MS) >= call.fromDate)
          .slice(0, Math.min(call.limit, policy.reads.maxRowsPerCall))
          .map((tx) => ({
            transactionId: tx.transactionId,
            amountMinor: tx.amountMinor,
            currency: 'USD' as const,
            date: transactionDate(tx, FIXTURE_EPOCH_MS),
            // Unlabelled until src/untrusted.ts (#10) lands.
            description: { text: tx.description, trust: 'external_untrusted' as const, riskSignals: [] },
          }));
        log('read.executed', agentId, { tool: call.tool });
        return { ok: true, result: { transactions } };
      }
      case 'af_propose_transfer':
        return proposeTransfer(agentId, call);
      case 'af_get_transfer_status': {
        const t = transfers.get(call.transferRef);
        if (!t || t.agentId !== agentId) return deny(agentId, call.tool, 'INVALID_ARGUMENTS');
        expire(t);
        return { ok: true, result: { state: t.state, reasonCode: t.reasonCode, updatedAt: t.updatedAt } };
      }
    }
  }

  return {
    async handleCall(agentId, tool, args) {
      // Args are untrusted values, not just JSON: a getter or Proxy can throw mid-check.
      // The contract is to deny, never reject.
      try {
        return handle(agentId, tool, args);
      } catch {
        log('policy.denied', policy.agentId, { reasonCode: 'INTERNAL_UNAVAILABLE' });
        return { ok: false, error: { code: 'INTERNAL_UNAVAILABLE', message: 'INTERNAL_UNAVAILABLE' } };
      }
    },

    async listPending() {
      const out: PendingApproval[] = [];
      for (const t of transfers.values()) {
        expire(t);
        if (t.state === 'PENDING_APPROVAL' && t.pending) out.push(structuredClone(t.pending));
      }
      return out;
    },

    async approve(reservationId, digest, nonce) {
      return settle(reservationId, nonce, digest);
    },

    async reject(reservationId, nonce) {
      return settle(reservationId, nonce, null);
    },

    async revoke(agentId) {
      if (agentId !== policy.agentId) return;
      revoked.add(agentId);
      for (const t of transfers.values()) {
        if (t.agentId === agentId && t.state === 'PENDING_APPROVAL') {
          t.state = 'REJECTED';
          t.reasonCode = 'SESSION_REVOKED';
          t.updatedAt = iso();
        }
      }
      log('session.revoked', agentId);
    },

    async isRevoked(agentId) {
      return revoked.has(agentId);
    },

    async recordRefusedConnection(refused = 1) {
      const count = Number.isInteger(refused) && refused > 0 ? refused : 1;
      // Never rejects, like handleCall: the socket server must not have to guard against us.
      try {
        log('action.attempted', policy.agentId, { metadata: { reason: 'connection_limit', refused: count } });
      } catch {
        // Nothing to fall back to: the log is the only place this goes.
      }
    },

    async recordOAuthEvent(event, app) {
      // Never rejects, like recordRefusedConnection.
      try {
        log(event, policy.agentId, { metadata: { client: cleanAppText(app.client), redirectHost: cleanAppText(app.redirectHost) } });
      } catch {
        // Nothing to fall back to: the log is the only place this goes.
      }
    },

    async getPolicy() {
      return { policy: structuredClone(policy), version };
    },

    async updatePolicy(next, expectedVersion): Promise<PolicyUpdateResult> {
      if (expectedVersion !== version) return { ok: false, code: 'VERSION_CONFLICT' };
      const parsed = Policy.safeParse(next);
      if (!parsed.success || parsed.data.agentId !== policy.agentId) return { ok: false, code: 'INVALID_POLICY' };
      const oldHash = requestHash(policy);
      policy = parsed.data;
      version += 1;
      log('policy.updated', policy.agentId, { metadata: { oldHash, newHash: requestHash(policy) } });
      return { ok: true, version };
    },

    async getOverview(): Promise<Overview> {
      const all = [...transfers.values()].filter((t) => t.agentId === policy.agentId);
      for (const t of all) expire(t);
      // No rolling windows here: everything that holds budget counts.
      const held = all.filter((t) => !['FAILED', 'REJECTED', 'EXPIRED'].includes(t.state));
      return {
        usage: { reads: 0, transfers: held.length, transferredMinor: held.reduce((sum, t) => sum + t.call.amountMinor, 0) },
        balance: { balanceMinor: CHECKING_ACCOUNT.openingBalanceMinor, currency: 'USD', observedAt: iso() },
      };
    },

    async listTransfers(limit = 20): Promise<TransferSummary[]> {
      const all = [...transfers.values()].filter((t) => t.agentId === policy.agentId);
      for (const t of all) expire(t);
      return all.reverse().slice(0, limit).map((t) => ({
        reservationId: t.ref, payeeId: t.call.payeeId, amountMinor: t.call.amountMinor, currency: t.call.currency,
        state: t.state, reasonCode: t.reasonCode, createdAt: t.createdAt, updatedAt: t.updatedAt,
      }));
    },

    async listActivity(filter: ActivityFilter = {}) {
      const limit = filter.limit ?? DEFAULT_ACTIVITY_LIMIT;
      if (!Number.isInteger(limit) || limit < 1) throw new RangeError(`invalid activity limit: ${limit}`);
      const events = filter.events;
      const matching = events ? activity.filter((e) => events.includes(e.event)) : activity;
      return structuredClone(matching.slice(-Math.min(limit, MAX_ACTIVITY_LIMIT)).reverse());
    },
  };
}
