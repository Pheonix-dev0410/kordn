import { describe, expect, it } from 'vitest';
import { CHECKING_ACCOUNT, PAYEES, TRANSACTIONS, transactionDate } from '../src/mock-bank.js';
import { ResourceId } from '../src/schema.js';

describe('mock bank data', () => {
  it('has one account, two payees and twenty transactions', () => {
    expect(ResourceId.parse(CHECKING_ACCOUNT.resourceId)).toBe('mock-bank:checking-01');
    expect(PAYEES.map((p) => p.payeeId)).toEqual(['utilities', 'landlord']);
    expect(TRANSACTIONS).toHaveLength(20);
    expect(new Set(TRANSACTIONS.map((t) => t.transactionId)).size).toBe(20);
  });

  it('includes injection memos', () => {
    expect(TRANSACTIONS.filter((t) => t.injection).length).toBe(5);
  });

  it('is deterministic', () => {
    expect(transactionDate(TRANSACTIONS[0]!)).toBe('2026-10-24');
  });
});
