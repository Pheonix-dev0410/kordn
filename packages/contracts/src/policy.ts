import { z } from 'zod';
import { AgentId, AmountMinor, Currency, PayeeId, ResourceId } from './primitives';

// First released policy schema (§6.2). Every object is strict: unknown keys fail closed.

export const ReadPolicy = z.strictObject({
  allow: z.boolean(),
  maxCalls: z.number().int().min(0),
  windowSec: z.number().int().positive(),
  maxRowsPerCall: z.number().int().min(1).max(20),
  maxLookbackDays: z.number().int().min(1).max(30),
});

export const TransferPolicy = z.strictObject({
  allow: z.boolean(),
  maxCalls: z.number().int().min(0),
  windowSec: z.number().int().positive(),
  currency: Currency,
  maxSingleMinor: AmountMinor,
  maxCumulativeMinor: AmountMinor,
  allowedPayeeIds: z.array(PayeeId).max(64),
  humanApprovalAboveMinor: z.number().int().min(0),
});

export const Policy = z
  .strictObject({
    schemaVersion: z.literal(1),
    policyId: z.string().min(1).max(128),
    agentId: AgentId,
    defaultDecision: z.literal('deny'),
    resourceId: ResourceId,
    reads: ReadPolicy,
    transfers: TransferPolicy,
  })
  .superRefine((p, ctx) => {
    if (p.transfers.maxSingleMinor > p.transfers.maxCumulativeMinor) {
      ctx.addIssue({
        code: 'custom',
        path: ['transfers', 'maxSingleMinor'],
        message: 'maxSingleMinor must not exceed maxCumulativeMinor',
      });
    }
    if (new Set(p.transfers.allowedPayeeIds).size !== p.transfers.allowedPayeeIds.length) {
      ctx.addIssue({ code: 'custom', path: ['transfers', 'allowedPayeeIds'], message: 'duplicate payee id' });
    }
  });

export type Policy = z.infer<typeof Policy>;
