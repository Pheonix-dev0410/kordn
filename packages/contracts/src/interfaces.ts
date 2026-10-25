import type { AdapterResult } from './adapter';
import type { AuditEvent } from './audit';
import type { Decision, PolicyVerdict } from './decision';
import type { LifecycleState } from './lifecycle';
import type { Policy } from './policy';
import type { AgentId, TransferRef } from './primitives';
import type { ProposeTransfer, ToolOutput, TypedAction } from './tools';

// Module contracts (§5.1). Implementations live in their own packages; these
// types are the seams that let the packages be built in parallel.

/** Operating mode; only `contain` may claim sandbox-backed protection. */
export type CoverageMode = 'observe' | 'guard' | 'contain';

/** Identity bound by the trusted launcher to an IPC connection. Never from the payload. */
export interface TrustedIdentity {
  readonly agentId: AgentId;
  readonly sessionId: string;
  readonly coverage: CoverageMode;
}

export interface Clock {
  nowMs(): number;
}

/** Usage snapshot inside the rolling windows, read by the guardian inside BEGIN IMMEDIATE. */
export interface UsageSnapshot {
  readonly reads: { readonly count: number };
  readonly transfers: { readonly count: number; readonly sumMinor: number };
}

export interface EvaluateInput {
  readonly identity: TrustedIdentity;
  readonly action: TypedAction;
  readonly policy: Policy;
  readonly policyVersion: number;
  readonly revoked: boolean;
  readonly usage: UsageSnapshot;
  /** Guardian DB time, used e.g. for the lookback check on af_list_transactions. */
  readonly nowMs: number;
}

/** packages/policy: pure, deterministic, no I/O, no LLM. Implements §6.3 precedence. */
export type EvaluatePolicy = (input: EvaluateInput) => PolicyVerdict;

/** packages/adapter-mock: the only code that touches the mock bank. Idempotent by reservationId. */
export interface BankAdapter {
  getBalance(resourceId: string): Promise<ToolOutput<'af_get_balance'>>;
  listTransactions(resourceId: string, fromDate: string, limit: number): Promise<ToolOutput<'af_list_transactions'>>;
  execute(reservationId: string, action: ProposeTransfer): Promise<AdapterResult>;
  reconcile(reservationId: string): Promise<AdapterResult>;
}

export interface ReservationView {
  readonly id: string;
  readonly transferRef: TransferRef;
  readonly agentId: AgentId;
  readonly state: LifecycleState;
  readonly payeeId: string;
  readonly amountMinor: number;
  readonly createdMs: number;
  readonly requestHash: string;
}

/** packages/guardian: the only component allowed to mutate budgets. */
export interface Guardian {
  /** Entry point for one IPC frame. `tool` and `args` are untrusted and unparsed. */
  handleCall(identity: TrustedIdentity, tool: unknown, args: unknown): Promise<unknown>;
  authorizeAndReserve(identity: TrustedIdentity, action: ProposeTransfer): Promise<Decision>;
  finalize(reservationId: string, result: AdapterResult): Promise<void>;
  /** Resolve UNKNOWN reservations via the adapter; never releases quota without a trusted result. */
  reconcile(): Promise<void>;
  /** Kill switch: new actions denied, pending approvals invalidated. */
  revoke(agentId: AgentId): Promise<void>;
}

export interface IsolationCheck {
  readonly id: string;
  readonly description: string;
  readonly passed: boolean;
  readonly detail: string;
}

/** Produced by packages/launcher; displayed by admin-ui. `contain` only if every check passed. */
export interface CoverageReport {
  readonly mode: CoverageMode;
  readonly checkedAt: string;
  readonly imageDigest: string | null;
  readonly checks: readonly IsolationCheck[];
  readonly protectedTools: readonly string[];
  readonly unprotectedWarnings: readonly string[];
}

export interface ApprovalView {
  readonly reservationId: string;
  readonly agentId: AgentId;
  readonly payeeId: string;
  readonly amountMinor: number;
  readonly currency: 'USD';
  readonly resourceId: string;
  readonly policyVersion: number;
  readonly digest: string;
  readonly expiresAt: string;
  /** One-use nonce the approve/reject call must echo back (§8.5). */
  readonly nonce: string;
}

export interface AuditFilter {
  readonly agentId?: AgentId;
  readonly states?: readonly LifecycleState[];
  readonly sinceMs?: number;
  readonly limit?: number;
}

/**
 * Host-only admin surface implemented by the guardian and consumed by admin-ui
 * over loopback (§10). Never exposed through the broker socket.
 */
export interface AdminApi {
  getPolicy(agentId: AgentId): Promise<{ policy: Policy; version: number; revoked: boolean }>;
  /** Optimistic concurrency: fails if expectedVersion is stale. Logs old/new policy hashes. */
  updatePolicy(agentId: AgentId, policy: Policy, expectedVersion: number): Promise<{ version: number }>;
  listPendingApprovals(agentId: AgentId): Promise<readonly ApprovalView[]>;
  /** Re-checks revocation and all limits; can never override a hard deny. */
  approve(reservationId: string, digest: string, nonce: string): Promise<Decision>;
  reject(reservationId: string, nonce: string): Promise<void>;
  revoke(agentId: AgentId): Promise<void>;
  listReservations(filter: AuditFilter): Promise<readonly ReservationView[]>;
  listAudit(filter: AuditFilter): Promise<readonly AuditEvent[]>;
  coverage(): Promise<CoverageReport>;
}
