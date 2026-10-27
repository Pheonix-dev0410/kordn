import { readFileSync } from 'node:fs';
import { z } from 'zod';
import { PayPalAdapter } from './paypal.js';
import { PlaidAdapter } from './plaid.js';
import type { BankAdapter, Policy } from './schema.js';
import { StripeAdapter } from './stripe.js';

// --bank <file>: a real payment provider instead of the mock bank, with the user's own
// account. The file says which provider and maps policy payees to the provider's ids (Plaid,
// read-only, has none: it names the bank account instead). API keys come only from the
// environment, never from the file. `live: true`, which kordn setup writes when you choose
// real money, does what --live does.

const Payees = (id: RegExp) => z.record(z.string(), z.string().regex(id)).refine((p) => Object.keys(p).length > 0, 'add at least one payee');

export const BankConfig = z.discriminatedUnion('provider', [
  z.strictObject({
    provider: z.literal('stripe'),
    payees: Payees(/^acct_[A-Za-z0-9]+$/),
    live: z.literal(true).optional(),
  }),
  z.strictObject({
    provider: z.literal('paypal'),
    payees: Payees(/^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/),
    live: z.literal(true).optional(),
  }),
  z.strictObject({
    provider: z.literal('plaid'),
    accountId: z.string().regex(/^[A-Za-z0-9_-]{1,128}$/),
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

/** Whether this account is a real one: live money, or a real bank through Plaid production. */
export function isLive(config: BankConfig, env: NodeJS.ProcessEnv, live = false): boolean {
  if (config.provider === 'plaid') return /^access-production-/.test(env.PLAID_ACCESS_TOKEN ?? '');
  return live || config.live === true;
}

/**
 * The adapter for this config and policy. Refuses a mismatch that would make transfers fail
 * or go somewhere unexpected, and live keys unless `live` (or the file's `live`) is set: test
 * mode is the default. PayPal credentials don't show which environment they're for, so there
 * `live` picks it.
 */
export function openBank(config: BankConfig, policy: Policy, env: NodeJS.ProcessEnv, liveFlag = false, fetchImpl?: typeof fetch): BankAdapter {
  const provider = config.provider;
  const live = isLive(config, env, liveFlag);
  if (!policy.resourceId.startsWith(`${provider}:`)) {
    throw new Error(`the policy's resourceId ${policy.resourceId} is not a ${provider} account; use ${provider}:<name>`);
  }
  const need = (name: string) => {
    const value = env[name];
    if (!value) throw new Error(`set ${name} to your ${provider} API key`);
    return value;
  };
  // Read-only, so no payees to map, and no money to put behind --live.
  if (config.provider === 'plaid') {
    const accessToken = env.PLAID_ACCESS_TOKEN;
    if (!accessToken) throw new Error('set PLAID_ACCESS_TOKEN: run kordn setup to connect a bank through Plaid');
    return new PlaidAdapter({ clientId: need('PLAID_CLIENT_ID'), secret: need('PLAID_SECRET'), accessToken, accountId: config.accountId, fetch: fetchImpl });
  }
  const unmapped = policy.transfers.allowedPayeeIds.filter((p) => !Object.hasOwn(config.payees, p));
  if (unmapped.length) throw new Error(`the bank file has no ${provider} id for payee ${unmapped.join(', ')}`);

  if (config.provider === 'paypal') {
    return new PayPalAdapter({ clientId: need('PAYPAL_CLIENT_ID'), clientSecret: need('PAYPAL_CLIENT_SECRET'), payees: config.payees, live, fetch: fetchImpl });
  }
  const apiKey = need('STRIPE_API_KEY');
  if (!/^(sk|rk)_test_/.test(apiKey) && !live) throw new Error('that is a live stripe key; kordn uses test keys unless you pass --live');
  return new StripeAdapter({ apiKey, payees: config.payees, fetch: fetchImpl });
}
