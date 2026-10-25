import { z } from 'zod';

// Result of a trusted adapter execution (§5.2). `unknown` must hold the
// reservation until reconcile() proves the outcome (INV-06).
export const AdapterResult = z.discriminatedUnion('state', [
  z.strictObject({ state: z.literal('succeeded'), receiptId: z.string().min(1) }),
  z.strictObject({ state: z.literal('failed'), reasonCode: z.string().min(1) }),
  z.strictObject({ state: z.literal('unknown'), correlationId: z.string().min(1) }),
]);
export type AdapterResult = z.infer<typeof AdapterResult>;
