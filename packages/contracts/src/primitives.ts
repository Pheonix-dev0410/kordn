import { z } from 'zod';

// Upper bound for any minor-unit amount. Anything larger is rejected at the
// schema layer so it never reaches ledger arithmetic (T09 "huge integer").
export const MAX_AMOUNT_MINOR = 1_000_000_000_00;

export const AgentId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
export type AgentId = z.infer<typeof AgentId>;

export const ResourceId = z.string().regex(/^mock-bank:[a-z0-9-]{1,64}$/);
export type ResourceId = z.infer<typeof ResourceId>;

export const PayeeId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);
export type PayeeId = z.infer<typeof PayeeId>;

export const IdempotencyKey = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/);
export type IdempotencyKey = z.infer<typeof IdempotencyKey>;

/** Guardian-issued opaque reference; agents must never be able to forge one. */
export const TransferRef = z.string().regex(/^tr_[A-Za-z0-9_-]{16,64}$/);
export type TransferRef = z.infer<typeof TransferRef>;

/** v0.1 supports USD only, no FX (§6.1). */
export const Currency = z.literal('USD');
export type Currency = z.infer<typeof Currency>;

/** Strictly positive integer in minor units (cents). Rejects 0, negatives, floats, NaN, huge values. */
export const AmountMinor = z.number().int().positive().max(MAX_AMOUNT_MINOR);

/** Signed ledger amount for transaction history (debits negative). */
export const SignedAmountMinor = z.number().int().min(-MAX_AMOUNT_MINOR).max(MAX_AMOUNT_MINOR);

export const IsoDate = z.iso.date();
export const IsoDateTime = z.iso.datetime();

export const Sha256Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);
export type Sha256Digest = z.infer<typeof Sha256Digest>;
