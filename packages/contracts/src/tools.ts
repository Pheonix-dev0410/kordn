import { z } from 'zod';
import {
  AmountMinor,
  Currency,
  IdempotencyKey,
  IsoDate,
  IsoDateTime,
  PayeeId,
  ResourceId,
  SignedAmountMinor,
  TransferRef,
} from './primitives';
import { LifecycleState } from './lifecycle';

// The ONLY four agent-facing tools in v0.1 (§7.1). Anything else is UNKNOWN_ACTION.
export const TOOL_NAMES = [
  'af_get_balance',
  'af_list_transactions',
  'af_propose_transfer',
  'af_get_transfer_status',
] as const;
export const ToolName = z.enum(TOOL_NAMES);
export type ToolName = z.infer<typeof ToolName>;

// ---- Inputs (what the agent sends; untrusted until parsed) ----

export const GetBalanceInput = z.strictObject({ resourceId: ResourceId });

export const ListTransactionsInput = z.strictObject({
  resourceId: ResourceId,
  fromDate: IsoDate,
  limit: z.number().int().min(1).max(20),
});

export const ProposeTransferInput = z.strictObject({
  resourceId: ResourceId,
  payeeId: PayeeId,
  amountMinor: AmountMinor,
  currency: Currency,
  idempotencyKey: IdempotencyKey,
});

export const GetTransferStatusInput = z.strictObject({ transferRef: TransferRef });

export const TOOL_INPUTS = {
  af_get_balance: GetBalanceInput,
  af_list_transactions: ListTransactionsInput,
  af_propose_transfer: ProposeTransferInput,
  af_get_transfer_status: GetTransferStatusInput,
} as const satisfies Record<ToolName, z.ZodType>;

/** A parsed, schema-valid request. Agent identity is NOT part of it (comes from the launcher-bound IPC peer). */
export const TypedAction = z.discriminatedUnion('tool', [
  GetBalanceInput.extend({ tool: z.literal('af_get_balance') }),
  ListTransactionsInput.extend({ tool: z.literal('af_list_transactions') }),
  ProposeTransferInput.extend({ tool: z.literal('af_propose_transfer') }),
  GetTransferStatusInput.extend({ tool: z.literal('af_get_transfer_status') }),
]);
export type TypedAction = z.infer<typeof TypedAction>;
export type ProposeTransfer = Extract<TypedAction, { tool: 'af_propose_transfer' }>;

// ---- Outputs (what the guardian returns; minimized) ----

/** Text that originated outside the trust boundary (memos, page text). Data, never instructions (§7.3). */
export const UntrustedText = z.strictObject({
  text: z.string().max(2000),
  trust: z.literal('external_untrusted'),
  riskSignals: z.array(z.enum(['instruction_like_text', 'contains_url', 'contains_payee_like_id'])),
});
export type UntrustedText = z.infer<typeof UntrustedText>;

export const GetBalanceOutput = z.strictObject({
  currency: Currency,
  balanceMinor: SignedAmountMinor,
  observedAt: IsoDateTime,
});

export const TransactionRow = z.strictObject({
  transactionId: z.string().regex(/^txn-[0-9]{3,}$/),
  amountMinor: SignedAmountMinor,
  currency: Currency,
  date: IsoDate,
  description: UntrustedText,
});

export const ListTransactionsOutput = z.strictObject({
  transactions: z.array(TransactionRow).max(20),
});

export const ProposeTransferOutput = z.strictObject({
  state: z.enum(['denied', 'pending_approval', 'succeeded', 'failed', 'unknown']),
  transferRef: TransferRef.nullable(),
  reasonCode: z.string().nullable(),
});

export const GetTransferStatusOutput = z.strictObject({
  state: LifecycleState,
  reasonCode: z.string().nullable(),
  updatedAt: IsoDateTime,
});

export const TOOL_OUTPUTS = {
  af_get_balance: GetBalanceOutput,
  af_list_transactions: ListTransactionsOutput,
  af_propose_transfer: ProposeTransferOutput,
  af_get_transfer_status: GetTransferStatusOutput,
} as const satisfies Record<ToolName, z.ZodType>;

export type ToolOutput<T extends ToolName> = z.infer<(typeof TOOL_OUTPUTS)[T]>;

/** Parse untrusted (tool, args) into a TypedAction, or null. Never throws. */
export function parseToolCall(tool: unknown, args: unknown): TypedAction | null {
  const name = ToolName.safeParse(tool);
  if (!name.success) return null;
  const parsed = TOOL_INPUTS[name.data].safeParse(args);
  if (!parsed.success) return null;
  return { tool: name.data, ...parsed.data } as TypedAction;
}
