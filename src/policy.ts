import { parseToolCall, TOOL_NAMES } from './schema.js';
import type { EvaluateInput, Verdict } from './schema.js';

/** Pure policy evaluation. Usage must include committed, budget-holding reservations. */
export function evaluate({ agentId, call, policy, revoked, usage, nowMs }: EvaluateInput): Verdict {
  const deny = (code: Extract<Verdict, { kind: 'deny' }>['code']): Verdict => ({ kind: 'deny', code });
  if (revoked) return deny('SESSION_REVOKED');
  if (!TOOL_NAMES.includes(call.tool)) return deny('UNKNOWN_ACTION');
  if (agentId !== policy.agentId || ('resourceId' in call && call.resourceId !== policy.resourceId)) {
    return deny('INVALID_ARGUMENTS');
  }

  if (call.tool === 'af_propose_transfer') {
    const limits = policy.transfers;
    if (!limits.allow) return deny('CAPABILITY_DISABLED');
    if (!limits.allowedPayeeIds.includes(call.payeeId)) return deny('UNAPPROVED_PAYEE');
    const { tool, ...args } = call;
    if (!parseToolCall(tool, args) || call.currency !== limits.currency) return deny('INVALID_ARGUMENTS');
    if (call.amountMinor > limits.maxSingleMinor) return deny('SINGLE_LIMIT');
    if (usage.transfers >= limits.maxCalls) return deny('FREQUENCY_LIMIT');
    if (call.amountMinor > limits.maxCumulativeMinor - usage.transferredMinor) return deny('CUMULATIVE_LIMIT');
    return call.amountMinor > limits.humanApprovalAboveMinor ? { kind: 'require_approval' } : { kind: 'allow' };
  }

  const { tool, ...args } = call;
  if (!parseToolCall(tool, args)) return deny('INVALID_ARGUMENTS');
  // Internal status polling has its own rate limit in the ledger.
  if (call.tool === 'af_get_transfer_status') return { kind: 'allow' };
  if (!policy.reads.allow) return deny('CAPABILITY_DISABLED');
  if (call.tool === 'af_list_transactions') {
    const dayMs = 86_400_000;
    const todayMs = Math.floor(nowMs / dayMs) * dayMs;
    const fromMs = Date.parse(call.fromDate);
    if (!Number.isFinite(todayMs) || !(fromMs <= todayMs)) return deny('INVALID_ARGUMENTS');
    if (fromMs < todayMs - policy.reads.maxLookbackDays * dayMs) return deny('LOOKBACK_LIMIT');
    if (call.limit > policy.reads.maxRowsPerCall) return deny('ROW_LIMIT');
  }
  if (usage.reads >= policy.reads.maxCalls) return deny('FREQUENCY_LIMIT');
  return { kind: 'allow' };
}
