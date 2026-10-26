import { chmodSync, linkSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import fixture from '../examples/policy.json' with { type: 'json' };
import { Policy } from '../src/schema.js';
import { Ledger } from '../src/ledger.js';
import { MockBankAdapter } from '../src/mock-bank.js';
import { harness, propose, transfer } from './helpers.js';

let h: ReturnType<typeof harness> | undefined;
afterEach(() => { vi.restoreAllMocks(); h?.close(); h = undefined; });

describe('security regression probes', () => {
  it.each([['count', false], ['total', false], ['count', true], ['total', true]] as const)(
    'holds a newly completed old reservation against the current rolling %s limit (lost response: %s)', async (limit, responseLost) => {
    const policy = Policy.parse(fixture);
    policy.transfers.windowSec = 1;
    policy.transfers.maxCalls = limit === 'count' ? 1 : 100;
    policy.transfers.maxSingleMinor = 5000;
    policy.transfers.maxCumulativeMinor = limit === 'count' ? 25000 : 5000;
    h = harness(policy);
    h.bank.faults.responseLost = responseLost;
    const first = propose(h);
    h.advance(2000); // A slow adapter completes after the admission window has ended.
    expect((await first).state).toBe(responseLost ? 'unknown' : 'succeeded');
    if (responseLost) await h.guardian.reconcile();
    h.bank.faults.responseLost = false;
    await expect(propose(h, 1)).rejects.toMatchObject({ code: limit === 'count' ? 'FREQUENCY_LIMIT' : 'CUMULATIVE_LIMIT' });
    h.advance(1000);
    expect((await propose(h, 2)).state).toBe('succeeded');
  });

  it('rejects databases in a directory accessible to other users', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-permissions-'));
    const publicDir = join(dir, 'public');
    mkdirSync(publicDir, { mode: 0o755 });
    chmodSync(publicDir, 0o755);
    try {
      for (const create of [() => new Ledger(join(publicDir, 'ledger.sqlite')), () => new MockBankAdapter(join(publicDir, 'bank.sqlite'))]) {
        let opened: { close(): void } | undefined;
        try { expect(() => { opened = create(); }).toThrow('private directory'); }
        finally { opened?.close(); }
      }
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('returns unknown when reconciliation also reports unknown during an active execution', async () => {
    h = harness();
    vi.spyOn(h.bank, 'reconcile').mockResolvedValue({ state: 'unknown', correlationId: 'still-running' });
    vi.spyOn(h.bank, 'execute').mockImplementation(async (id) => {
      await h!.guardian.reconcile();
      return { state: 'unknown', correlationId: id };
    });
    await expect(propose(h)).resolves.toMatchObject({ state: 'unknown' });
    expect(h.ledger.list()[0]!.state).toBe('UNKNOWN');
  });

  it('creates private databases and rejects symlinks and hard links', () => {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-files-'));
    try {
      const target = join(dir, 'target.sqlite');
      writeFileSync(target, '', { mode: 0o644 });
      const ledger = new Ledger(target);
      try {
        for (const suffix of ['', '-wal', '-shm']) expect(statSync(target + suffix).mode & 0o777).toBe(0o600);
      } finally { ledger.close(); }
      const soft = join(dir, 'soft.sqlite');
      symlinkSync(target, soft);
      expect(() => new Ledger(soft)).toThrow();
      const hard = join(dir, 'hard.sqlite');
      linkSync(target, hard);
      expect(() => new Ledger(hard)).toThrow('hard links');
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  it('rejects hostile payloads without executing or logging the supplied text', async () => {
    h = harness();
    const execute = vi.spyOn(h.bank, 'execute');
    const { tool, ...args } = transfer();
    const attacks = [null, [], 'secret-marker', { ...args, amountMinor: '5000' },
      { ...args, policyApproved: true }, { ...args, nonce: 'secret-marker' },
      { ...args, payeeId: "utilities'; DROP TABLE policies;--" },
      { ...args, resourceId: 'mock-bank:other' }, { ...args, agentId: 'other-agent' },
      JSON.parse(JSON.stringify(args).replace(/}$/, ',"__proto__":{"admin":true}}'))];
    for (const attack of attacks) await expect(h.guardian.handleCall(h.policy.agentId, tool, attack)).resolves.toMatchObject({ ok: false, error: { code: expect.any(String) } });
    expect(execute).not.toHaveBeenCalled();
    expect(h.ledger.list()).toHaveLength(0);
    expect(JSON.stringify(await h.guardian.listActivity())).not.toContain('secret-marker');
    expect((await h.guardian.getPolicy()).policy.agentId).toBe(fixture.agentId);
  });

  it('executes only once when two approvals race with the same nonce', async () => {
    h = harness();
    await propose(h, 0, 8000);
    const pending = (await h.guardian.listPending())[0]!;
    const results = await Promise.allSettled([
      h.guardian.approve(pending.reservationId, pending.digest, pending.nonce!),
      h.guardian.approve(pending.reservationId, pending.digest, pending.nonce!),
    ]);
    expect(results.filter((r) => r.status === 'fulfilled' && r.value.ok)).toHaveLength(1);
    expect((await h.bank.getBalance(h.policy.resourceId)).balanceMinor).toBe(482315 - 8000);
    expect(h.ledger.audit.verifyChain()).toBe(true);
  });

  it('fails closed against an actual read-only SQLite database', async () => {
    h = harness();
    const execute = vi.spyOn(h.bank, 'execute');
    h.ledger.db.exec('PRAGMA query_only=ON');
    await expect(propose(h)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect(execute).not.toHaveBeenCalled();
    expect(h.ledger.list()).toHaveLength(0);
  });

  it('retains quota if audit storage fails after the bank has already applied a transfer', async () => {
    const policy = Policy.parse(fixture);
    policy.transfers.maxCalls = 1;
    h = harness(policy);
    const execute = h.bank.execute.bind(h.bank);
    const spy = vi.spyOn(h.bank, 'execute').mockImplementation(async (id, call) => {
      const result = await execute(id, call);
      h!.ledger.db.exec("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'storage unavailable'); END");
      return result;
    });
    await expect(propose(h)).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect(h.ledger.list()[0]!.state).toBe('DISPATCHING');
    h.ledger.db.exec('DROP TRIGGER fail_audit');
    await expect(propose(h, 1)).rejects.toMatchObject({ code: 'FREQUENCY_LIMIT' });
    await h.guardian.reconcile();
    expect((await propose(h)).state).toBe('succeeded');
    expect(spy).toHaveBeenCalledTimes(1);
    expect((await h.bank.getBalance(policy.resourceId)).balanceMinor).toBe(482315 - 5000);
    expect(h.ledger.audit.verifyChain()).toBe(true);
  });
});
