import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { PayPalAdapter } from './paypal.js';
import type { BankAdapter, Policy } from './schema.js';
import { StripeAdapter } from './stripe.js';

// --bank <file>: a real payment provider instead of the mock bank, with the user's own
// account. The file says which provider and maps policy payees to the provider's ids. API
// keys come only from the environment, never from the file.

const Payees = (id: RegExp) => z.record(z.string(), z.string().regex(id)).refine((p) => Object.keys(p).length > 0, 'add at least one payee');

export const BankConfig = z.discriminatedUnion('provider', [
  z.strictObject({
    provider: z.literal('stripe'),
    payees: Payees(/^acct_[A-Za-z0-9]+$/),
  }),
  z.strictObject({
    provider: z.literal('paypal'),
    payees: Payees(/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/),
  }),
]);
export type BankConfig = z.infer<typeof BankConfig>;

export function loadBankConfig(path: string): BankConfig {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    throw new Error(`invalid bank file ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed = BankConfig.safeParse(raw);
  if (!parsed.success) throw new Error(`invalid bank file ${path}:\n${z.prettifyError(parsed.error)}`);
  return parsed.data;
}

/**
 * The adapter for this config and policy. Refuses a mismatch that would make transfers fail
 * or go somewhere unexpected, and live keys unless `live` is set: test mode is the default.
 * PayPal credentials don't show which environment they're for, so there `live` picks it.
 */
export function openBank(config: BankConfig, policy: Policy, env: NodeJS.ProcessEnv, live = false, fetchImpl?: typeof fetch): BankAdapter {
  const provider = config.provider;
  if (!policy.resourceId.startsWith(`${provider}:`)) {
    throw new Error(`the policy's resourceId ${policy.resourceId} is not a ${provider} account; use ${provider}:<name>`);
  }
  const unmapped = policy.transfers.allowedPayeeIds.filter((p) => !Object.hasOwn(config.payees, p));
  if (unmapped.length) throw new Error(`the bank file has no ${provider} id for payee ${unmapped.join(', ')}`);

  const need = (name: string) => {
    const value = env[name];
    if (!value) throw new Error(`set ${name} to your ${provider} API key`);
    return value;
  };
  if (config.provider === 'paypal') {
    return new PayPalAdapter({ clientId: need('PAYPAL_CLIENT_ID'), clientSecret: need('PAYPAL_CLIENT_SECRET'), payees: config.payees, live, fetch: fetchImpl });
  }
  const apiKey = need('STRIPE_API_KEY');
  if (!/^(sk|rk)_test_/.test(apiKey) && !live) throw new Error('that is a live stripe key; kordn uses test keys unless you pass --live');
  return new StripeAdapter({ apiKey, payees: config.payees, fetch: fetchImpl });
}
