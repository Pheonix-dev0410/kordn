import { z } from 'zod';

// Action lifecycle (§8.1). RECONCILED from the design doc is modelled as the
// `transfer.reconciled` audit event plus the resolved SUCCEEDED/FAILED state,
// so a row's state alone always says whether it consumes budget.
export const LIFECYCLE_STATES = [
  'REQUESTED',
  'DENIED',
  'RESERVED',
  'PENDING_APPROVAL',
  'APPROVED',
  'REJECTED',
  'EXPIRED',
  'DISPATCHING',
  'SUCCEEDED',
  'FAILED',
  'UNKNOWN',
] as const;
export const LifecycleState = z.enum(LIFECYCLE_STATES);
export type LifecycleState = z.infer<typeof LifecycleState>;

export const ALLOWED_TRANSITIONS: Readonly<Record<LifecycleState, readonly LifecycleState[]>> = {
  REQUESTED: ['DENIED', 'RESERVED'],
  RESERVED: ['PENDING_APPROVAL', 'DISPATCHING', 'REJECTED'],
  PENDING_APPROVAL: ['APPROVED', 'REJECTED', 'EXPIRED'],
  APPROVED: ['DISPATCHING', 'REJECTED'],
  DISPATCHING: ['SUCCEEDED', 'FAILED', 'UNKNOWN'],
  UNKNOWN: ['SUCCEEDED', 'FAILED'],
  DENIED: [],
  REJECTED: [],
  EXPIRED: [],
  SUCCEEDED: [],
  FAILED: [],
};

/**
 * States that count against rolling transfer limits (INV-03, INV-06).
 * APPROVED is included even though §8.1 omits it: an approved-but-not-yet-dispatched
 * reservation must keep holding its headroom.
 */
export const BUDGET_CONSUMING_STATES: readonly LifecycleState[] = [
  'RESERVED',
  'PENDING_APPROVAL',
  'APPROVED',
  'DISPATCHING',
  'UNKNOWN',
  'SUCCEEDED',
];

export function canTransition(from: LifecycleState, to: LifecycleState): boolean {
  return ALLOWED_TRANSITIONS[from].includes(to);
}

export function isTerminal(state: LifecycleState): boolean {
  return ALLOWED_TRANSITIONS[state].length === 0;
}
