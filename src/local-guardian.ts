import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { Guardian } from './guardian.js';
import { requestHash } from './hash.js';
import { Ledger } from './ledger.js';
import { MockBankAdapter } from './mock-bank.js';
import type { Policy } from './schema.js';

// The real guardian on disk: the ledger and the mock bank, each in its own SQLite file in
// one private directory.

/** Where kordn keeps its state unless --data says otherwise. */
export function defaultDataDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'kordn');
}

export interface LocalGuardian {
  guardian: Guardian;
  close(): void;
}

/**
 * The stored policy wins, so edits made in the admin UI survive a restart. `replacePolicy`
 * (an explicit --policy) makes the given one the new version instead. Reconciles before
 * returning, so transfers a crash left in flight are settled before any new call.
 */
export async function openLocalGuardian(dir: string, policy: Policy, replacePolicy = false): Promise<LocalGuardian> {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  let ledger: Ledger | undefined;
  let bank: MockBankAdapter | undefined;
  try {
    ledger = new Ledger(join(dir, 'ledger.sqlite'));
    bank = new MockBankAdapter(join(dir, 'bank.sqlite'));
    const stored = storedPolicy(ledger, policy.agentId);
    if (!stored) ledger.updatePolicy(policy, 0);
    else if (replacePolicy && requestHash(stored.policy) !== requestHash(policy)) ledger.updatePolicy(policy, stored.version);
    const guardian = new Guardian(ledger, bank, policy.agentId);
    await guardian.reconcile();
    const opened = { ledger, bank };
    return { guardian, close: () => (opened.ledger.close(), opened.bank.close()) };
  } catch (error) {
    ledger?.close();
    bank?.close();
    if (error instanceof Error && error.message === 'database needs a private directory') {
      throw new Error(`${dir} must be readable only by you (chmod 700)`);
    }
    throw error;
  }
}

function storedPolicy(ledger: Ledger, agentId: string): { policy: Policy; version: number } | null {
  try {
    return ledger.getPolicy(agentId);
  } catch {
    return null;
  }
}
