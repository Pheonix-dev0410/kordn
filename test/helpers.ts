import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import fixture from '../examples/policy.json' with { type: 'json' };
import { GuardianError, Ledger } from '../src/ledger.js';
import { Guardian } from '../src/guardian.js';
import { FIXTURE_EPOCH_MS, MockBankAdapter } from '../src/mock-bank.js';
import { Policy, TOOL_OUTPUTS } from '../src/schema.js';
import type { TransferCall } from '../src/schema.js';

export function harness(policy = Policy.parse(fixture), timeoutMs = 1000) {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-'));
  let now = FIXTURE_EPOCH_MS;
  const clock = { nowMs: () => now };
  const ledger = new Ledger(join(dir, 'ledger.sqlite'), clock);
  ledger.updatePolicy(policy, 0);
  const bank = new MockBankAdapter(join(dir, 'bank.sqlite'), clock);
  const guardian = new Guardian(ledger, bank, policy.agentId, timeoutMs);
  return { dir, clock, ledger, bank, guardian, policy, advance: (ms: number) => { now += ms; },
    restart() {
      this.ledger.close();
      this.bank.close();
      this.ledger = new Ledger(join(dir, 'ledger.sqlite'), clock);
      this.bank = new MockBankAdapter(join(dir, 'bank.sqlite'), clock);
      this.guardian = new Guardian(this.ledger, this.bank, policy.agentId, timeoutMs);
    },
    close() { this.ledger.close(); this.bank.close(); rmSync(dir, { recursive: true, force: true }); } };
}

export function transfer(index = 0, amountMinor = 5000): TransferCall {
  return { tool: 'af_propose_transfer', resourceId: fixture.resourceId, payeeId: 'utilities',
    amountMinor, currency: 'USD', idempotencyKey: `request-${String(index).padStart(8, '0')}` };
}

export async function propose(h: ReturnType<typeof harness>, index = 0, amountMinor = 5000) {
  const { tool, ...args } = transfer(index, amountMinor);
  const result = await h.guardian.handleCall(h.policy.agentId, tool, args);
  if (!result.ok) throw new GuardianError(result.error.code);
  const output = TOOL_OUTPUTS.af_propose_transfer.parse(result.result);
  if (!output.transferRef) throw new Error('missing transfer reference');
  return { ...output, transferRef: output.transferRef };
}
