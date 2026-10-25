import { randomBytes } from 'node:crypto';
import type {
  ActivityFilter,
  ApprovalResult,
  CallResult,
  Guardian,
  PendingApproval,
  PolicyUpdateResult,
} from './guardian-api.js';
import { requestHash } from './hash.js';
import { CHECKING_ACCOUNT, FIXTURE_EPOCH_MS, TRANSACTIONS, transactionDate } from './mock-bank.js';
import {
  type AuditEvent,
  type DenyCode,
  parseToolCall,
  Policy,
  type State,
  ToolName,
  type TransferCall,
} from './schema.js';

// In-memory stand-in for the guardian (#6) so the MCP server and admin UI can be built
// and tested before it lands. Enforces only payee, single limit and approval threshold.
// No ledger, no rolling limits, no persistence. Not a security boundary.

const APPROVAL_TTL_MS = 15 * 60_000;

interface Transfer {
  ref: string;
  agentId: string;
  call: TransferCall;
  state: State;
  reasonCode: string | null;
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
  const usedNonces = new Set<string>();
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

  function deny(agentId: string, tool: AuditEvent['tool'], code: DenyCode, hash: string | null = null): CallResult {
    log('policy.denied', agentId, { tool, reasonCode: code, requestHash: hash });
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

  function proposeTransfer(agentId: string, call: TransferCall): CallResult {
    const hash = requestHash(call);
    const rules = policy.transfers;
    if (call.resourceId !== policy.resourceId) return deny(agentId, call.tool, 'UNKNOWN_ACTION', hash);
    if (!rules.allow) return deny(agentId, call.tool, 'CAPABILITY_DISABLED', hash);
    if (!rules.allowedPayeeIds.includes(call.payeeId)) return deny(agentId, call.tool, 'UNAPPROVED_PAYEE', hash);
    if (call.amountMinor > rules.maxSingleMinor) return deny(agentId, call.tool, 'SINGLE_LIMIT', hash);

    const ref = `tr_${token(16)}`;
    const t: Transfer = { ref, agentId, call, state: 'RESERVED', reasonCode: null, updatedAt: iso() };
    transfers.set(ref, t);

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
        expiresAt: new Date(now() + APPROVAL_TTL_MS).toISOString(),
      };
      log('policy.require_approval', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
      return { ok: true, result: { state: 'pending_approval', transferRef: ref, reasonCode: null } };
    }

    t.state = 'SUCCEEDED';
    log('policy.allowed', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
    log('transfer.succeeded', agentId, { tool: call.tool, requestHash: hash, reservationId: ref });
    return { ok: true, result: { state: 'succeeded', transferRef: ref, reasonCode: null } };
  }

  function settle(reservationId: string, nonce: string, digest: string | null): ApprovalResult {
    const t = transfers.get(reservationId);
    if (t) expire(t);
    if (!t?.pending || t.state !== 'PENDING_APPROVAL') return { ok: false, code: t?.state === 'EXPIRED' ? 'APPROVAL_EXPIRED' : 'NOT_PENDING' };
    if (nonce !== t.pending.nonce || usedNonces.has(nonce)) return { ok: false, code: 'BAD_NONCE' };
    if (digest !== null && digest !== t.pending.digest) return { ok: false, code: 'STALE_DIGEST' };
    usedNonces.add(nonce);
    if (digest === null) {
      t.state = 'REJECTED';
      t.updatedAt = iso();
      log('approval.rejected', t.agentId, { tool: 'af_propose_transfer', reservationId });
      return { ok: true };
    }
    // Approval can't override a hard deny: re-check against the current policy.
    const code: DenyCode | null = revoked.has(t.agentId)
      ? 'SESSION_REVOKED'
      : !policy.transfers.allowedPayeeIds.includes(t.call.payeeId)
        ? 'UNAPPROVED_PAYEE'
        : t.call.amountMinor > policy.transfers.maxSingleMinor
          ? 'SINGLE_LIMIT'
          : null;
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

  return {
    async handleCall(agentId, tool, args) {
      const name = ToolName.safeParse(tool);
      const toolName = name.success ? name.data : null;
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
          log('read.executed', agentId, { tool: call.tool });
          return {
            ok: true,
            result: { currency: 'USD', balanceMinor: CHECKING_ACCOUNT.openingBalanceMinor, observedAt: iso() },
          };
        case 'af_list_transactions': {
          if (call.resourceId !== policy.resourceId) return deny(agentId, call.tool, 'UNKNOWN_ACTION');
          if (!policy.reads.allow) return deny(agentId, call.tool, 'CAPABILITY_DISABLED');
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
    },

    async listPending() {
      const out: PendingApproval[] = [];
      for (const t of transfers.values()) {
        expire(t);
        if (t.state === 'PENDING_APPROVAL' && t.pending) out.push({ ...t.pending });
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

    async getPolicy() {
      return { policy, version };
    },

    async updatePolicy(next, expectedVersion): Promise<PolicyUpdateResult> {
      if (expectedVersion !== version) return { ok: false, code: 'VERSION_CONFLICT' };
      const parsed = Policy.safeParse(next);
      if (!parsed.success) return { ok: false, code: 'INVALID_POLICY' };
      const oldHash = requestHash(policy);
      policy = parsed.data;
      version += 1;
      log('policy.updated', policy.agentId, { metadata: { oldHash, newHash: requestHash(policy) } });
      return { ok: true, version };
    },

    async listActivity(filter: ActivityFilter = {}) {
      const events = filter.events;
      const matching = events ? activity.filter((e) => events.includes(e.event)) : activity;
      return matching
        .slice()
        .reverse()
        .slice(0, filter.limit ?? 100);
    },
  };
}
