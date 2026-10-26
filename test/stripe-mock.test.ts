import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import fixture from '../examples/policy.json' with { type: 'json' };
import { Guardian } from '../src/guardian.js';
import { Ledger } from '../src/ledger.js';
import { Policy } from '../src/schema.js';
import { StripeAdapter } from '../src/stripe.js';

// The Stripe adapter against stripe-mock (github.com/stripe/stripe-mock), which is built
// from Stripe's OpenAPI spec and rejects unknown endpoints, unknown parameters and wrong
// types. It's stateless, so this checks what we send and that we can read what comes back,
// not Stripe's behaviour. Runs when STRIPE_MOCK_URL is set, as in CI.

const url = process.env.STRIPE_MOCK_URL;
const policy = Policy.parse({ ...fixture, resourceId: 'stripe:main' });

describe.runIf(url)('Stripe adapter against stripe-mock', () => {
  const bank = new StripeAdapter({ apiKey: 'sk_test_123', payees: { utilities: 'acct_utilities01', landlord: 'acct_landlord01' }, api: url });
  const dir = mkdtempSync(join(tmpdir(), 'kordn-stripe-mock-'));
  const ledger = new Ledger(join(dir, 'ledger.sqlite'));
  ledger.updatePolicy(policy, 0);
  const guardian = new Guardian(ledger, bank, policy.agentId);
  afterAll(() => {
    ledger.close();
    rmSync(dir, { recursive: true, force: true });
  });

  it('rejects a request Stripe would reject, so the checks below mean something', async () => {
    const res = await fetch(`${url}/v1/transfers`, {
      method: 'POST',
      headers: { authorization: 'Bearer sk_test_123', 'content-type': 'application/x-www-form-urlencoded' },
      body: 'amount=100&currency=usd&destination=acct_x&made_up_field=1',
    });
    expect(res.status).toBe(400);
  });

  it('accepts the transfer kordn sends', async () => {
    const result = await guardian.handleCall(policy.agentId, 'af_propose_transfer', {
      resourceId: policy.resourceId,
      payeeId: 'utilities',
      amountMinor: 5_000,
      currency: 'USD',
      idempotencyKey: 'stripe-mock-1',
    });
    expect(result).toMatchObject({ ok: true, result: { state: 'succeeded' } });
  });

  it('accepts the lookup by transfer group', async () => {
    expect(await bank.reconcile(ledger.list()[0]!.id)).toMatchObject({ state: 'succeeded', receiptId: expect.stringMatching(/^tr_/) });
  });

  it('accepts the balance and transaction reads and parses the replies', async () => {
    expect(await bank.getBalance(policy.resourceId)).toMatchObject({ currency: 'USD' });
    const { transactions } = await bank.listTransactions(policy.resourceId, '2026-10-01', 20);
    expect(transactions.length).toBeGreaterThan(0);
    expect(transactions[0]!.description.riskSignals).toBeDefined();
  });
});
