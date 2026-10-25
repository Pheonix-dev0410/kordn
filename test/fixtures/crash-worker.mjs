import { join } from 'node:path';
import { Ledger } from '../../dist/ledger.js';
import { Guardian } from '../../dist/guardian.js';
import { FIXTURE_EPOCH_MS, MockBankAdapter } from '../../dist/mock-bank.js';
import { serveGuardian } from '../../dist/socket.js';

const [dir, stage] = process.argv.slice(2);
const clock = { nowMs: () => FIXTURE_EPOCH_MS };
const ledger = new Ledger(join(dir, 'ledger.sqlite'), clock);
const bank = new MockBankAdapter(join(dir, 'bank.sqlite'), clock);
const agentId = 'sandbox-demo-01';
if (stage === 'socket') {
  await serveGuardian(new Guardian(ledger, bank, agentId), join(dir, 'guardian.sock'));
  process.send({ stage });
} else {
  const admission = ledger.admit(agentId, {
    tool: 'af_propose_transfer', resourceId: 'mock-bank:checking-01', payeeId: 'utilities',
    amountMinor: 5000, currency: 'USD', idempotencyKey: 'request-00000000',
  });
  if (admission.kind !== 'transfer') throw new Error('missing reservation');
  const r = admission.reservation;
  if (stage === 'response-lost') {
    ledger.dispatch(r.id);
    bank.faults.responseLost = true;
    const result = await bank.execute(r.id, r.call);
    if (result.state !== 'unknown') throw new Error('fault did not fire');
    // Deliberately stop before persisting the response in the guardian ledger.
  }
  process.send({ stage, id: r.id });
}
setInterval(() => {}, 1000);
