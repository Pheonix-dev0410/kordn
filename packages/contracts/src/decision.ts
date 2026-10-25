import { z } from 'zod';
import { IsoDateTime, Sha256Digest } from './primitives';

// Reason codes (§6.3), plus IDEMPOTENCY_CONFLICT from §8.4 and RATE_LIMITED for
// status polling / proposal flooding (§6.4, §10.2).
export const DENY_CODES = [
  'SESSION_REVOKED',
  'ISOLATION_FAILED',
  'UNKNOWN_ACTION',
  'INVALID_ARGUMENTS',
  'CAPABILITY_DISABLED',
  'UNAPPROVED_PAYEE',
  'SINGLE_LIMIT',
  'FREQUENCY_LIMIT',
  'CUMULATIVE_LIMIT',
  'APPROVAL_EXPIRED',
  'INTERNAL_UNAVAILABLE',
  'IDEMPOTENCY_CONFLICT',
  'RATE_LIMITED',
] as const;
export const DenyCode = z.enum(DENY_CODES);
export type DenyCode = z.infer<typeof DenyCode>;

/** Output of the pure policy evaluator. It never allocates reservations. */
export const PolicyVerdict = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('deny'), code: DenyCode }),
  z.strictObject({ kind: z.literal('allow') }),
  z.strictObject({ kind: z.literal('require_approval') }),
]);
export type PolicyVerdict = z.infer<typeof PolicyVerdict>;

/** Guardian decision after the atomic ledger step (§5.2). */
export const Decision = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('deny'), code: DenyCode, policyVersion: z.number().int().min(0) }),
  z.strictObject({ kind: z.literal('allow'), reservationId: z.string().min(1), digest: Sha256Digest }),
  z.strictObject({
    kind: z.literal('require_approval'),
    reservationId: z.string().min(1),
    digest: Sha256Digest,
    expiresAt: IsoDateTime,
  }),
]);
export type Decision = z.infer<typeof Decision>;
