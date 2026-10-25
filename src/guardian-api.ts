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

export type ApprovalError = 'NOT_PENDING' | 'STALE_DIGEST' | 'BAD_NONCE' | 'APPROVAL_EXPIRED' | 'SESSION_REVOKED' | DenyCode;

export type ApprovalResult = { ok: true } | { ok: false; code: ApprovalError };

export type PolicyUpdateResult = { ok: true; version: number } | { ok: false; code: 'VERSION_CONFLICT' | 'INVALID_POLICY' };

export interface ActivityFilter {
  events?: AuditEvent['event'][];
  limit?: number;
}

export interface Guardian {
  /** Agent identity comes from the caller (stdio process or socket), never from args. */
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
