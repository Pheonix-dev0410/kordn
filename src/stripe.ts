import { TOOL_OUTPUTS } from './schema.js';
import type { AdapterResult, BankAdapter, TransferCall } from './schema.js';
import { labelUntrusted } from './untrusted.js';

// Stripe transfers (USD) to connected accounts, with the user's own key. The agent only names
// payees from the policy; this maps them to connected account ids. Every transfer carries the
// reservation id as its Idempotency-Key and transfer_group, so a retry is never a second
// transfer and a restart can look it up instead of sending again.
// API: https://docs.stripe.com/api/transfers/create

const API = 'https://api.stripe.com';

export interface StripeOptions {
  apiKey: string;
  /** Policy payee id to Stripe connected account id (acct_...). */
  payees: Record<string, string>;
  fetch?: typeof fetch;
}

interface Transfer {
  id: string;
  reversed?: boolean;
}

export class StripeAdapter implements BankAdapter {
  private readonly fetch: typeof fetch;

  constructor(private readonly o: StripeOptions) {
    this.fetch = o.fetch ?? fetch;
  }

  private async request<T>(method: 'GET' | 'POST', path: string, form?: Record<string, string>, headers: Record<string, string> = {}): Promise<T> {
    const res = await this.fetch(`${API}${path}`, {
      method,
      headers: { authorization: `Bearer ${this.o.apiKey}`, 'content-type': 'application/x-www-form-urlencoded', ...headers },
      body: form && new URLSearchParams(form).toString(),
      signal: AbortSignal.timeout(8_000),
    });
    const json = (await res.json().catch(() => ({}))) as T & { error?: { code?: string; type?: string } };
    // 5xx, 429 and 409 (the same key still in flight) mean we don't know: throw, so the guardian holds the quota.
    if (res.status >= 500 || res.status === 429 || res.status === 409) throw new Error(`stripe ${res.status}`);
    if (!res.ok) throw new RejectedError(`stripe:${json.error?.code ?? json.error?.type ?? res.status}`);
    return json;
  }

  async getBalance(_resourceId: string) {
    const { available } = await this.request<{ available: { amount: number; currency: string }[] }>('GET', '/v1/balance');
    return TOOL_OUTPUTS.af_get_balance.parse({
      currency: 'USD',
      balanceMinor: available.filter((b) => b.currency === 'usd').reduce((sum, b) => sum + b.amount, 0),
      observedAt: new Date().toISOString(),
    });
  }

  async listTransactions(_resourceId: string, fromDate: string, limit: number) {
    const query = new URLSearchParams({ 'created[gte]': String(Math.floor(Date.parse(fromDate) / 1000)), limit: String(limit) });
    const { data } = await this.request<{ data: StripeTransaction[] }>('GET', `/v1/balance_transactions?${query}`);
    return TOOL_OUTPUTS.af_list_transactions.parse({
      transactions: data
        .filter((tx) => tx.currency === 'usd')
        .slice(0, limit)
        .map((tx) => ({
          transactionId: tx.id,
          amountMinor: tx.amount,
          currency: 'USD',
          date: new Date(tx.created * 1000).toISOString().slice(0, 10),
          description: labelUntrusted(tx.description || tx.type || 'transaction'),
        })),
    });
  }

  async execute(reservationId: string, call: TransferCall): Promise<AdapterResult> {
    const destination = this.o.payees[call.payeeId];
    if (!destination) return { state: 'failed', reasonCode: 'PAYEE_NOT_MAPPED' };
    if (call.currency !== 'USD') return { state: 'failed', reasonCode: 'CURRENCY_NOT_SUPPORTED' };
    try {
      const transfer = await this.request<Transfer>(
        'POST',
        '/v1/transfers',
        { amount: String(call.amountMinor), currency: 'usd', destination, transfer_group: reservationId, description: 'kordn' },
        { 'idempotency-key': reservationId },
      );
      return { state: 'succeeded', receiptId: transfer.id };
    } catch (error) {
      if (error instanceof RejectedError) return { state: 'failed', reasonCode: error.message };
      throw error;
    }
  }

  async reconcile(reservationId: string): Promise<AdapterResult> {
    const query = new URLSearchParams({ transfer_group: reservationId, limit: '1' });
    const { data } = await this.request<{ data: Transfer[] }>('GET', `/v1/transfers?${query}`);
    const transfer = data[0];
    // No transfer in our group: Stripe never created it.
    if (!transfer) return { state: 'failed', reasonCode: 'NOT_EXECUTED' };
    return transfer.reversed ? { state: 'failed', reasonCode: 'stripe:reversed' } : { state: 'succeeded', receiptId: transfer.id };
  }
}

interface StripeTransaction {
  id: string;
  amount: number;
  currency: string;
  created: number;
  description?: string | null;
  type?: string;
}

/** Stripe refused the request outright (4xx): nothing was sent. */
class RejectedError extends Error {}
