import { TOOL_OUTPUTS } from './schema.js';
import type { AdapterResult, BankAdapter, TransferCall } from './schema.js';
import { labelUntrusted } from './untrusted.js';

// RazorpayX payouts (India, INR) with the user's own keys. The agent only names payees
// from the policy; this maps them to the user's RazorpayX fund accounts. Every payout
// carries the reservation id as its idempotency key and reference_id, so a retry is never
// a second payout and a restart can ask RazorpayX what happened instead of sending again.
// API: https://razorpay.com/docs/api/x/payouts/create/bank-account/

const API = 'https://api.razorpay.com';

export interface RazorpayXOptions {
  keyId: string;
  keySecret: string;
  /** The account payouts are made from: your Customer Identifier or Current Account number. */
  accountNumber: string;
  /** NEFT, RTGS or IMPS for bank accounts; UPI for VPA fund accounts. */
  mode: 'NEFT' | 'RTGS' | 'IMPS' | 'UPI';
  /** Policy payee id to RazorpayX fund account id (fa_...). */
  payees: Record<string, string>;
  fetch?: typeof fetch;
}

interface Payout {
  id: string;
  status: string;
  utr?: string | null;
}

export class RazorpayXAdapter implements BankAdapter {
  private readonly fetch: typeof fetch;

  constructor(private readonly o: RazorpayXOptions) {
    this.fetch = o.fetch ?? fetch;
  }

  private async request<T>(method: 'GET' | 'POST', path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const auth = Buffer.from(`${this.o.keyId}:${this.o.keySecret}`).toString('base64');
    const res = await this.fetch(`${API}${path}`, {
      method,
      headers: { authorization: `Basic ${auth}`, 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(8_000),
    });
    const json = (await res.json().catch(() => ({}))) as T & { error?: { code?: string } };
    // 5xx and 429 mean we don't know what happened: throw, so the guardian holds the quota.
    if (res.status >= 500 || res.status === 429) throw new Error(`razorpayx ${res.status}`);
    if (!res.ok) throw new RejectedError(`razorpayx:${json.error?.code ?? res.status}`);
    return json;
  }

  async getBalance(_resourceId: string) {
    const { items } = await this.request<{ items: { account_number: string; amount: number; available_amount?: number }[] }>(
      'GET',
      '/v1/banking_balances',
    );
    const account = items.find((a) => a.account_number === this.o.accountNumber);
    if (!account) throw new Error('razorpayx account not found');
    return TOOL_OUTPUTS.af_get_balance.parse({
      currency: 'INR',
      balanceMinor: account.available_amount ?? account.amount,
      observedAt: new Date().toISOString(),
    });
  }

  async listTransactions(_resourceId: string, fromDate: string, limit: number) {
    const from = Math.floor(Date.parse(fromDate) / 1000);
    const query = new URLSearchParams({ account_number: this.o.accountNumber, from: String(from), count: String(limit) });
    const { items } = await this.request<{ items: RazorpayTransaction[] }>('GET', `/v1/transactions?${query}`);
    return TOOL_OUTPUTS.af_list_transactions.parse({
      transactions: items.slice(0, limit).map((tx) => ({
        transactionId: tx.id,
        amountMinor: tx.debit > 0 ? -tx.debit : tx.credit,
        currency: 'INR',
        date: new Date(tx.created_at * 1000).toISOString().slice(0, 10),
        description: labelUntrusted(describe(tx.source)),
      })),
    });
  }

  async execute(reservationId: string, call: TransferCall): Promise<AdapterResult> {
    const fundAccountId = this.o.payees[call.payeeId];
    if (!fundAccountId) return { state: 'failed', reasonCode: 'PAYEE_NOT_MAPPED' };
    if (call.currency !== 'INR') return { state: 'failed', reasonCode: 'CURRENCY_NOT_SUPPORTED' };
    try {
      const payout = await this.request<Payout>(
        'POST',
        '/v1/payouts',
        {
          account_number: this.o.accountNumber,
          fund_account_id: fundAccountId,
          amount: call.amountMinor,
          currency: 'INR',
          mode: this.o.mode,
          purpose: 'payout',
          queue_if_low_balance: false,
          reference_id: reservationId,
          narration: 'kordn',
        },
        { 'x-payout-idempotency': reservationId },
      );
      return outcome(payout);
    } catch (error) {
      if (error instanceof RejectedError) return { state: 'failed', reasonCode: error.message };
      throw error;
    }
  }

  async reconcile(reservationId: string): Promise<AdapterResult> {
    const query = new URLSearchParams({ account_number: this.o.accountNumber, reference_id: reservationId });
    const { items } = await this.request<{ items: Payout[] }>('GET', `/v1/payouts?${query}`);
    // No payout with our reference: RazorpayX never created it.
    return items[0] ? outcome(items[0]) : { state: 'failed', reasonCode: 'NOT_EXECUTED' };
  }
}

interface RazorpayTransaction {
  id: string;
  credit: number;
  debit: number;
  created_at: number;
  source?: { entity?: string; payer_name?: string; narration?: string; notes?: Record<string, unknown> } | null;
}

/** Text from outside kordn, labelled untrusted before the agent sees it. */
function describe(source: RazorpayTransaction['source']): string {
  const notes = Object.values(source?.notes ?? {}).filter((v): v is string => typeof v === 'string');
  return [source?.narration, source?.payer_name, ...notes].filter(Boolean).join(' ') || source?.entity || 'transaction';
}

function outcome(payout: Payout): AdapterResult {
  if (payout.status === 'processed') return { state: 'succeeded', receiptId: payout.utr || payout.id };
  if (['queued', 'pending', 'processing'].includes(payout.status)) return { state: 'unknown', correlationId: payout.id };
  return { state: 'failed', reasonCode: `razorpayx:${payout.status}` };
}

/** RazorpayX refused the request outright (4xx): nothing was sent. */
class RejectedError extends Error {}
