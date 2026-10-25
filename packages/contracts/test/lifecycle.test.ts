import { describe, expect, it } from 'vitest';
import { BUDGET_CONSUMING_STATES, canTransition, isTerminal, LIFECYCLE_STATES } from '../src';

describe('lifecycle', () => {
  it('never leaves a terminal state', () => {
    for (const s of ['DENIED', 'REJECTED', 'EXPIRED', 'SUCCEEDED', 'FAILED'] as const) {
      expect(isTerminal(s)).toBe(true);
      for (const t of LIFECYCLE_STATES) expect(canTransition(s, t)).toBe(false);
    }
  });

  it('UNKNOWN can only resolve to a trusted outcome (INV-06)', () => {
    expect(canTransition('UNKNOWN', 'SUCCEEDED')).toBe(true);
    expect(canTransition('UNKNOWN', 'FAILED')).toBe(true);
    expect(canTransition('UNKNOWN', 'REJECTED')).toBe(false);
    expect(canTransition('UNKNOWN', 'DISPATCHING')).toBe(false);
  });

  it('holds budget through approval, dispatch and unknown', () => {
    for (const s of ['RESERVED', 'PENDING_APPROVAL', 'APPROVED', 'DISPATCHING', 'UNKNOWN', 'SUCCEEDED'] as const) {
      expect(BUDGET_CONSUMING_STATES).toContain(s);
    }
    for (const s of ['DENIED', 'REJECTED', 'EXPIRED', 'FAILED'] as const) {
      expect(BUDGET_CONSUMING_STATES).not.toContain(s);
    }
  });
});
