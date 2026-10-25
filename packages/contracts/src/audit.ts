import { z } from 'zod';
import { AgentId, IsoDateTime, Sha256Digest } from './primitives';
import { DenyCode } from './decision';
import { ToolName } from './tools';

// Audit evidence (§10.3). INV-07: attempted, approved, executed, rejected and
// unknown must be distinguishable by `event`.
export const AUDIT_EVENT_KINDS = [
  'action.attempted',
  'policy.allowed',
  'policy.denied',
  'policy.require_approval',
  'read.executed',
  'approval.granted',
  'approval.rejected',
  'approval.expired',
  'transfer.dispatching',
  'transfer.succeeded',
  'transfer.failed',
  'transfer.unknown',
  'transfer.reconciled',
  'session.revoked',
  'policy.updated',
  'isolation.checked',
  'isolation.failed',
] as const;
export const AuditEventKind = z.enum(AUDIT_EVENT_KINDS);
export type AuditEventKind = z.infer<typeof AuditEventKind>;

export const AuditActor = z.enum(['guardian', 'admin', 'launcher', 'adapter']);

export const AuditEvent = z.strictObject({
  timestamp: IsoDateTime,
  event: AuditEventKind,
  actor: AuditActor,
  agent: AgentId,
  tool: ToolName.nullable(),
  requestHash: Sha256Digest.nullable(),
  policyVersion: z.number().int().min(0).nullable(),
  reasonCode: DenyCode.nullable(),
  reservationId: z.string().nullable(),
  /** Free-form, already sanitized metadata. Never secrets, tokens or raw prompts. */
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
  priorAuditHash: Sha256Digest.nullable(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;
