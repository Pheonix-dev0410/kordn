import { fork } from 'node:child_process';
import { once } from 'node:events';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, vi } from 'vitest';
import fixture from '../examples/policy.json' with { type: 'json' };
import { BUDGET_STATES, Policy } from '../src/schema.js';
import { callGuardian } from '../src/guardian-client.js';
import { harness, propose } from './helpers.js';

const runs = Number(process.env.KORDN_STRESS_RUNS ?? 1);
if (!Number.isSafeInteger(runs) || runs < 1 || runs > 1000) throw new Error('invalid KORDN_STRESS_RUNS');
let h: ReturnType<typeof harness>;
afterEach(() => { vi.restoreAllMocks(); h?.close(); });

async function checkpoint(dir: string, stage: string) {
  const child = fork(fileURLToPath(new URL('./fixtures/crash-worker.mjs', import.meta.url)), [dir, stage], {
    stdio: ['ignore', 'ignore', 'pipe', 'ipc'],
  });
  let stderr = '';
  child.stderr!.on('data', (data) => { stderr += String(data); });
  const message = new Promise<{ id: string }>((resolve, reject) => {
    child.once('message', (value) => resolve(value as { id: string }));
    child.once('error', reject);
    child.once('exit', () => reject(new Error(`worker exited before checkpoint: ${stderr}`)));
  });
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([message, new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`checkpoint timeout: ${stderr}`)), 10_000);
    })]);
    return { child, ...result };
  } catch (error) { child.kill('SIGKILL'); throw error; }
  finally { clearTimeout(timer); }
}

async function kill(child: ReturnType<typeof fork>) {
  const exited = once(child, 'exit');
  child.kill('SIGKILL');
  expect((await exited)[1]).toBe('SIGKILL');
}

describe.each(Array.from({ length: runs }, (_, i) => i + 1))('concurrency and crash run %i', () => {
  it.each(['count', 'total'])('caps 1,000 concurrent $50 proposals by %s', async (limit) => {
    const policy = Policy.parse(fixture);
    if (limit === 'total') policy.transfers.maxCalls = 1000;
    h = harness(policy);
    const results = await Promise.allSettled(Array.from({ length: 1000 }, (_, i) => propose(h, i)));
    const successes = results.filter((r) => r.status === 'fulfilled');
    expect(successes).toHaveLength(limit === 'count' ? 3 : 5);
    const reservations = h.ledger.list().filter((r) => BUDGET_STATES.includes(r.state));
    expect(reservations.length).toBeLessThanOrEqual(policy.transfers.maxCalls);
    expect(reservations.reduce((sum, r) => sum + r.call.amountMinor, 0)).toBeLessThanOrEqual(policy.transfers.maxCumulativeMinor);
    expect((await h.bank.getBalance(policy.resourceId)).balanceMinor).toBe(482315 - successes.length * 5000);
    expect(h.ledger.audit.verifyChain()).toBe(true);
    expect(results.filter((r) => r.status === 'rejected').every((r) => r.reason.code === (limit === 'count' ? 'FREQUENCY_LIMIT' : 'CUMULATIVE_LIMIT'))).toBe(true);
  }, 30_000);

  it.each(['reserved', 'response-lost'])('survives SIGKILL at %s without releasing quota or duplicating a transfer', async (stage) => {
    const policy = Policy.parse(fixture);
    policy.transfers.maxCalls = 1;
    h = harness(policy);
    const worker = await checkpoint(h.dir, stage);
    await kill(worker.child);
    h.restart();
    const r = h.ledger.get(worker.id)!;
    expect(r.state).toBe(stage === 'reserved' ? 'RESERVED' : 'DISPATCHING');
    await expect(propose(h, 1)).rejects.toMatchObject({ code: 'FREQUENCY_LIMIT' });
    expect((await propose(h)).transferRef).toBe(worker.id);
    const execute = vi.spyOn(h.bank, 'execute');
    await h.guardian.reconcile();
    expect(execute).not.toHaveBeenCalled();
    expect(h.ledger.get(worker.id)?.state).toBe(stage === 'reserved' ? 'REJECTED' : 'SUCCEEDED');
    await propose(h);
    expect((await h.bank.getBalance(policy.resourceId)).balanceMinor).toBe(482315 - (stage === 'reserved' ? 0 : 5000));
    expect(h.ledger.audit.verifyChain()).toBe(true);
  }, 15_000);

  it('fails explicitly when the guardian process is killed, with no bank fallback', async () => {
    h = harness();
    const worker = await checkpoint(h.dir, 'socket');
    const path = join(h.dir, 'guardian.sock');
    try {
      await expect(callGuardian(path, 'af_get_balance', { resourceId: h.policy.resourceId })).resolves.toHaveProperty('balanceMinor');
    } finally { await kill(worker.child); }
    await expect(callGuardian(path, 'af_get_balance', { resourceId: h.policy.resourceId })).rejects.toMatchObject({ code: 'INTERNAL_UNAVAILABLE' });
    expect((await h.bank.getBalance(h.policy.resourceId)).balanceMinor).toBe(482315);
  }, 15_000);
});
