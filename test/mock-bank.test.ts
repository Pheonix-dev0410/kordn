import { describe, expect, it } from 'vitest';
import { CHECKING_ACCOUNT, MockBankAdapter, PAYEES, TRANSACTIONS, transactionDate } from '../src/mock-bank.js';
import { ResourceId } from '../src/schema.js';
import { transfer } from './helpers.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

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

describe('mock bank adapter', () => {
  it('deduplicates transfers and rejects conflicting reservation payloads across restarts', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-bank-'));
    let bank = new MockBankAdapter(join(dir, 'bank.sqlite'));
    try {
      const initial = await bank.execute('reservation-1', transfer());
      expect(initial.state).toBe('succeeded');
      expect(await bank.execute('reservation-1', transfer())).toEqual(initial);
      bank.close();
      bank = new MockBankAdapter(join(dir, 'bank.sqlite'));
      expect(await bank.execute('reservation-1', transfer())).toEqual(initial);
      await expect(bank.execute('reservation-1', transfer(0, 5001))).rejects.toThrow('conflict');
      expect((await bank.getBalance(CHECKING_ACCOUNT.resourceId)).balanceMinor).toBe(CHECKING_ACCOUNT.openingBalanceMinor - 5000);
    } finally { bank.close(); rmSync(dir, { recursive: true, force: true }); }
  });

  it('reconciles an applied transfer whose response was lost', async () => {
    const bank = new MockBankAdapter(':memory:');
    try {
      bank.faults.responseLost = true;
      expect(await bank.execute('reservation-1', transfer())).toEqual({ state: 'unknown', correlationId: 'reservation-1' });
      expect((await bank.reconcile('reservation-1')).state).toBe('succeeded');
      expect((await bank.getBalance(CHECKING_ACCOUNT.resourceId)).balanceMinor).toBe(CHECKING_ACCOUNT.openingBalanceMinor - 5000);
    } finally { bank.close(); }
  });

  it('can reject or delay without duplicating or prematurely reconciling a send', async () => {
    const bank = new MockBankAdapter(':memory:');
    try {
      bank.faults.reject = true;
      expect((await bank.execute('rejected', transfer())).state).toBe('failed');
      expect((await bank.getBalance(CHECKING_ACCOUNT.resourceId)).balanceMinor).toBe(CHECKING_ACCOUNT.openingBalanceMinor);
      bank.faults = { delayMs: 30 };
      const first = bank.execute('delayed', transfer(1));
      expect((await bank.reconcile('delayed')).state).toBe('unknown');
      expect((await bank.execute('delayed', transfer(1))).state).toBe('unknown');
      expect((await first).state).toBe('succeeded');
      expect((await bank.reconcile('delayed')).state).toBe('succeeded');
    } finally { bank.close(); }
  });

  it('returns bounded transactions with untrusted memos and validates read arguments', async () => {
    const bank = new MockBankAdapter(':memory:');
    try {
      const result = await bank.listTransactions(CHECKING_ACCOUNT.resourceId, '2026-09-25', 20);
      expect(result.transactions).toHaveLength(18);
      expect(result.transactions.every((tx) => tx.description.trust === 'external_untrusted')).toBe(true);
      expect(result.transactions.filter((tx) => tx.description.riskSignals.includes('instruction_like_text'))).toHaveLength(5);
      expect((await bank.listTransactions(CHECKING_ACCOUNT.resourceId, '2026-10-24', 1)).transactions).toHaveLength(1);
      await expect(bank.listTransactions(CHECKING_ACCOUNT.resourceId, '2026-10-01', 21)).rejects.toThrow();
      await expect(bank.getBalance('mock-bank:other')).rejects.toThrow();
    } finally { bank.close(); }
  });

  it('binds a delayed execution to a snapshot of the validated call', async () => {
    const bank = new MockBankAdapter(':memory:');
    try {
      bank.faults.delayMs = 10;
      const call = transfer();
      const result = bank.execute('immutable', call);
      call.amountMinor = 9000;
      expect((await result).state).toBe('succeeded');
      expect((await bank.getBalance(CHECKING_ACCOUNT.resourceId)).balanceMinor).toBe(CHECKING_ACCOUNT.openingBalanceMinor - 5000);
    } finally { bank.close(); }
  });
});
