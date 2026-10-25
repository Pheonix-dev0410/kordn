import type { AuditEvent, DenyCode, Policy } from './schema.js';

// What the MCP server (#9), the sandbox launcher (#12) and the admin UI (#14, #15) need
// from the guardian (#6). src/fake-guardian.ts implements it until the real one lands.

export type CallResult = { ok: true; result: unknown } | { ok: false; error: { code: DenyCode; message: string } };

/** A transfer waiting for the user. Loaded from guardian storage, never from the agent. */
export interface PendingApproval {
  reservationId: string;
  agentId: string;
  resourceId: string;
  payeeId: string;
  amountMinor: number;
  currency: 'USD';
  policyVersion: number;
  /** requestHash of the canonical transfer. Approval is bound to it. */
  digest: string;
  /** One-use. A second approve or reject with the same nonce fails. */
  nonce: string;
  expiresAt: string;
}

export type ApprovalError = 'NOT_PENDING' | 'STALE_DIGEST' | 'BAD_NONCE' | DenyCode;

export type ApprovalResult = { ok: true } | { ok: false; code: ApprovalError };

export type PolicyUpdateResult = { ok: true; version: number } | { ok: false; code: 'VERSION_CONFLICT' | 'INVALID_POLICY' };

export interface ActivityFilter {
  events?: AuditEvent['event'][];
  /** A positive integer, default 100, capped at 1000. listActivity rejects anything else. */
  limit?: number;
}

/**
 * One instance serves exactly one agent: its policy's agentId, which a policy update can't
 * change. Calls for any other agent are denied with UNKNOWN_ACTION; revoke and isRevoked
 * for them are a no-op and false.
 */
export interface Guardian {
  // Every value returned is a copy: changing it never changes guardian state.

  /**
   * Agent identity comes from the caller (stdio process or socket), never from args.
   * Never rejects: an internal failure resolves to INTERNAL_UNAVAILABLE, so a broken
   * guardian denies rather than forwards. The other methods may reject on internal failure.
   */
  handleCall(agentId: string, tool: unknown, args: unknown): Promise<CallResult>;

  listPending(): Promise<PendingApproval[]>;
  /** Re-checks revocation and every limit. Can't override a hard deny. */
  approve(reservationId: string, digest: string, nonce: string): Promise<ApprovalResult>;
  reject(reservationId: string, nonce: string): Promise<ApprovalResult>;
  /** Denies new calls and rejects pending approvals, immediately. */
  revoke(agentId: string): Promise<void>;
  isRevoked(agentId: string): Promise<boolean>;

  getPolicy(): Promise<{ policy: Policy; version: number }>;
  updatePolicy(policy: unknown, expectedVersion: number): Promise<PolicyUpdateResult>;

  /** Newest first. */
  listActivity(filter?: ActivityFilter): Promise<AuditEvent[]>;
}
