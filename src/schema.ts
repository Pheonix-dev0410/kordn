import { z } from 'zod';

// Shared schemas and types. Every object is strict: unknown keys are rejected.

export const MAX_AMOUNT_MINOR = 100_000_000_000;

export const AgentId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,62}$/);
// The provider, then your name for the account: mock-bank:checking-01, stripe:main, paypal:main, plaid:main.
export const ResourceId = z.string().regex(/^(mock-bank|stripe|paypal|plaid):[a-z0-9-]{1,64}$/);
export const PayeeId = z.string().regex(/^[a-z0-9][a-z0-9-]{0,63}$/);
export const IdempotencyKey = z.string().regex(/^[A-Za-z0-9_-]{8,128}$/);
export const TransferRef = z.string().regex(/^tr_[A-Za-z0-9_-]{16,64}$/);
export const Currency = z.enum(['USD']);
export type Currency = z.infer<typeof Currency>;
export const AmountMinor = z.number().int().positive().max(MAX_AMOUNT_MINOR);
export const SignedAmountMinor = z.number().int().min(-MAX_AMOUNT_MINOR).max(MAX_AMOUNT_MINOR);
export const Digest = z.string().regex(/^sha256:[0-9a-f]{64}$/);

export const State = z.enum([
  'RESERVED',
  'PENDING_APPROVAL',
  'APPROVED',
  'REJECTED',
  'EXPIRED',
  'DISPATCHING',
  'SUCCEEDED',
  'FAILED',
  'UNKNOWN',
]);
export type State = z.infer<typeof State>;

// ---- Policy ----

export const Policy = z
  .strictObject({
    schemaVersion: z.literal(1),
    policyId: z.string().min(1).max(128),
    agentId: AgentId,
    defaultDecision: z.literal('deny'),
    resourceId: ResourceId,
    reads: z.strictObject({
      allow: z.boolean(),
      maxCalls: z.number().int().min(0),
      windowSec: z.number().int().positive(),
      maxRowsPerCall: z.number().int().min(1).max(20),
      maxLookbackDays: z.number().int().min(1).max(30),
    }),
    transfers: z.strictObject({
      allow: z.boolean(),
      maxCalls: z.number().int().min(0),
      windowSec: z.number().int().positive(),
      currency: Currency,
      maxSingleMinor: AmountMinor,
      maxCumulativeMinor: AmountMinor,
      allowedPayeeIds: z.array(PayeeId).max(64),
      humanApprovalAboveMinor: z.number().int().min(0),
    }),
  })
  .refine((p) => p.transfers.maxSingleMinor <= p.transfers.maxCumulativeMinor, {
    message: 'maxSingleMinor must not exceed maxCumulativeMinor',
  })
  .refine((p) => new Set(p.transfers.allowedPayeeIds).size === p.transfers.allowedPayeeIds.length, {
    message: 'duplicate payee id',
  });
export type Policy = z.infer<typeof Policy>;

// ---- Decisions ----

export const DenyCode = z.enum([
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
]);
export type DenyCode = z.infer<typeof DenyCode>;

/** Why a transfer ended up where it did, as the agent sees it. Adapter failures all map to ADAPTER_FAILED. */
export const TransferReasonCode = z.enum([...DenyCode.options, 'ADAPTER_FAILED']);
export type TransferReasonCode = z.infer<typeof TransferReasonCode>;

/** How long a pending transfer waits for the user before it expires. */
export const APPROVAL_TTL_SEC = 900;

/** Result of the pure policy check. Reservations are created by the guardian, not here. */
export type Verdict = { kind: 'deny'; code: DenyCode } | { kind: 'allow' } | { kind: 'require_approval' };

export type AdapterResult =
  | { state: 'succeeded'; receiptId: string }
  // Free text from the bank side: audit metadata at most, never returned to the agent.
  | { state: 'failed'; reasonCode: string }
  | { state: 'unknown'; correlationId: string };

// ---- Tools: the only four the agent can call ----

export const TOOL_NAMES = ['af_get_balance', 'af_list_transactions', 'af_propose_transfer', 'af_get_transfer_status'] as const;
export const ToolName = z.enum(TOOL_NAMES);
export type ToolName = z.infer<typeof ToolName>;

export const TOOL_INPUTS = {
  af_get_balance: z.strictObject({ resourceId: ResourceId }),
  af_list_transactions: z.strictObject({
    resourceId: ResourceId,
    fromDate: z.iso.date(),
    limit: z.number().int().min(1).max(20),
  }),
  af_propose_transfer: z.strictObject({
    resourceId: ResourceId,
    payeeId: PayeeId,
    amountMinor: AmountMinor,
    currency: Currency,
    idempotencyKey: IdempotencyKey,
  }),
  af_get_transfer_status: z.strictObject({ transferRef: TransferRef }),
} as const;

export type ToolCall = {
  [T in ToolName]: { tool: T } & z.infer<(typeof TOOL_INPUTS)[T]>;
}[ToolName];
export type TransferCall = Extract<ToolCall, { tool: 'af_propose_transfer' }>;

/** Parse untrusted (tool, args). Returns null for anything not exactly valid. */
export function parseToolCall(tool: unknown, args: unknown): ToolCall | null {
  const name = ToolName.safeParse(tool);
  if (!name.success) return null;
  const parsed = TOOL_INPUTS[name.data].safeParse(args);
  return parsed.success ? ({ tool: name.data, ...parsed.data } as ToolCall) : null;
}

/** Text from outside the trust boundary, e.g. transaction memos. Data, never instructions. */
export const UntrustedText = z.strictObject({
  text: z.string().max(2000),
  trust: z.literal('external_untrusted'),
  riskSignals: z.array(z.enum(['instruction_like_text', 'contains_url', 'contains_payee_like_id'])),
});

export const TOOL_OUTPUTS = {
  af_get_balance: z.strictObject({
    currency: Currency,
    balanceMinor: SignedAmountMinor,
    observedAt: z.iso.datetime(),
  }),
  af_list_transactions: z.strictObject({
    transactions: z
      .array(
        z.strictObject({
          transactionId: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/),
          amountMinor: SignedAmountMinor,
          currency: Currency,
          date: z.iso.date(),
          description: UntrustedText,
        }),
      )
      .max(20),
  }),
  // A denial is never a result: it is an error carrying a DenyCode (socket ok:false, MCP isError).
  // rejected and expired only describe an earlier transfer, reported again on an idempotent retry.
  af_propose_transfer: z.strictObject({
    state: z.enum(['pending_approval', 'succeeded', 'failed', 'unknown', 'rejected', 'expired']),
    transferRef: TransferRef.nullable(),
    reasonCode: TransferReasonCode.nullable(),
  }),
  af_get_transfer_status: z.strictObject({
    state: State,
    reasonCode: TransferReasonCode.nullable(),
    updatedAt: z.iso.datetime(),
  }),
} as const;

// ---- Transfer lifecycle ----

const TRANSITIONS: Record<State, State[]> = {
  RESERVED: ['PENDING_APPROVAL', 'DISPATCHING', 'REJECTED'],
  PENDING_APPROVAL: ['APPROVED', 'REJECTED', 'EXPIRED'],
  APPROVED: ['DISPATCHING', 'REJECTED'],
  DISPATCHING: ['SUCCEEDED', 'FAILED', 'UNKNOWN'],
  UNKNOWN: ['SUCCEEDED', 'FAILED'],
  REJECTED: [],
  EXPIRED: [],
  SUCCEEDED: [],
  FAILED: [],
};

/** States that count against rolling transfer limits. UNKNOWN holds quota until reconciled. */
export const BUDGET_STATES: readonly State[] = ['RESERVED', 'PENDING_APPROVAL', 'APPROVED', 'DISPATCHING', 'UNKNOWN', 'SUCCEEDED'];

export function canTransition(from: State, to: State): boolean {
  return TRANSITIONS[from].includes(to);
}

// ---- Audit log ----

export const AuditEvent = z.strictObject({
  timestamp: z.iso.datetime(),
  event: z.enum([
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
    'oauth.approved',
    'oauth.denied',
    'oauth.revoked',
    'oauth.refresh_reused',
  ]),
  agent: AgentId,
  tool: ToolName.nullable(),
  requestHash: Digest.nullable(),
  policyVersion: z.number().int().min(0).nullable(),
  reasonCode: DenyCode.nullable(),
  reservationId: z.string().nullable(),
  metadata: z.record(z.string(), z.union([z.string(), z.number(), z.boolean(), z.null()])),
  prevHash: Digest.nullable(),
});
export type AuditEvent = z.infer<typeof AuditEvent>;

// ---- Guardian socket protocol (used in sandbox mode) ----
// Newline-delimited JSON. No identity field: the guardian knows the agent from the socket.

export const MAX_FRAME_BYTES = 64 * 1024;

export const SocketRequest = z.strictObject({
  v: z.literal(1),
  id: z.string().min(1).max(64),
  tool: z.string().max(64),
  args: z.unknown(),
});

export type SocketResponse =
  | { v: 1; id: string; ok: true; result: unknown }
  | { v: 1; id: string; ok: false; error: { code: DenyCode; message: string } };

// ---- Interfaces between modules ----

export interface Clock {
  nowMs(): number;
}

export interface Usage {
  reads: number;
  transfers: number;
  transferredMinor: number;
}

export interface EvaluateInput {
  agentId: string;
  call: ToolCall;
  policy: Policy;
  revoked: boolean;
  usage: Usage;
  nowMs: number;
}

export interface BankAdapter {
  getBalance(resourceId: string): Promise<z.infer<(typeof TOOL_OUTPUTS)['af_get_balance']>>;
  listTransactions(
    resourceId: string,
    fromDate: string,
    limit: number,
  ): Promise<z.infer<(typeof TOOL_OUTPUTS)['af_list_transactions']>>;
  /** Must be idempotent by reservationId. */
  execute(reservationId: string, call: TransferCall): Promise<AdapterResult>;
  reconcile(reservationId: string): Promise<AdapterResult>;
}
