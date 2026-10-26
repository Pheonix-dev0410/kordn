import { TOOL_OUTPUTS } from './schema.js';
import type { AdapterResult, BankAdapter, TransferCall } from './schema.js';
import { labelUntrusted } from './untrusted.js';

// PayPal Payouts (USD) to PayPal accounts by email, with the user's own REST app. The agent
// only names payees from the policy; this maps them to emails. Every payout uses the
// reservation id as its sender_batch_id, which PayPal refuses to reuse for 30 days, so a
// retry is never a second payout.
//
// PayPal can't look a payout up by sender_batch_id, so reconcile sends a $0 batch with the
// same id instead. If the payout exists, PayPal refuses and links to it. If it doesn't, the
// $0 batch takes the id (PayPal denies it: ZERO_AMOUNT, nothing moves), so the original
// can't arrive late and pay after we've said it didn't.
// API: https://developer.paypal.com/docs/api/payments.payouts-batch/v1/

const SANDBOX = 'https://api-m.sandbox.paypal.com';
const LIVE = 'https://api-m.paypal.com';
const FENCE_ITEM = 'kordn-fence';

export interface PayPalOptions {
  clientId: string;
  clientSecret: string;
  /** Policy payee id to the PayPal account email that receives the payout. */
  payees: Record<string, string>;
  /** Sandbox unless true. PayPal credentials don't say which environment they're for. */
  live?: boolean;
  fetch?: typeof fetch;
}

interface Batch {
  batch_header: { payout_batch_id: string; batch_status: string };
  items?: { payout_item_id: string; transaction_id?: string; transaction_status: string; payout_item: { sender_item_id?: string } }[];
}

interface PayPalError {
  name?: string;
  details?: { field?: string; issue?: string; link?: { href?: string }[] }[];
}

export class PayPalAdapter implements BankAdapter {
  private readonly fetch: typeof fetch;
  private readonly api: string;
  private token?: { value: string; expiresAt: number };

  constructor(private readonly o: PayPalOptions) {
    this.fetch = o.fetch ?? fetch;
    this.api = o.live ? LIVE : SANDBOX;
  }

  private async accessToken(): Promise<string> {
    if (this.token && Date.now() < this.token.expiresAt) return this.token.value;
    const auth = Buffer.from(`${this.o.clientId}:${this.o.clientSecret}`).toString('base64');
    const res = await this.fetch(`${this.api}/v1/oauth2/token`, {
      method: 'POST',
      headers: { authorization: `Basic ${auth}`, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
      signal: AbortSignal.timeout(8_000),
    });
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error?: string };
    if (res.status >= 500 || res.status === 429) throw new Error(`paypal ${res.status}`);
    if (!res.ok || !json.access_token) throw new RejectedError(`paypal:${json.error ?? res.status}`);
    this.token = { value: json.access_token, expiresAt: Date.now() + Math.max(0, (json.expires_in ?? 0) - 60) * 1000 };
    return json.access_token;
  }

  private async request<T>(method: 'GET' | 'POST', path: string, body?: unknown, headers: Record<string, string> = {}): Promise<T> {
    const res = await this.fetch(`${this.api}${path}`, {
      method,
      headers: { authorization: `Bearer ${await this.accessToken()}`, 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(8_000),
    });
    const json = (await res.json().catch(() => ({}))) as T & PayPalError;
    // 5xx and 429 mean we don't know what happened: throw, so the guardian holds the quota.
    if (res.status >= 500 || res.status === 429) throw new Error(`paypal ${res.status}`);
    if (!res.ok) {
      const existing = duplicateOf(json);
      if (existing) throw new DuplicateError(existing);
      throw new RejectedError(`paypal:${json.name ?? res.status}`);
    }
    return json;
  }

  private async batch(id: string): Promise<AdapterResult> {
    return outcome(await this.request<Batch>('GET', `/v1/payments/payouts/${id}`));
  }

  async getBalance(_resourceId: string) {
    const { balances } = await this.request<{ balances?: { currency: string; total_balance: Money; available_balance?: Money }[] }>(
      'GET',
      '/v1/reporting/balances?currency_code=USD',
    );
    const usd = balances?.find((b) => b.currency === 'USD');
    if (!usd) throw new Error('paypal: no USD balance');
    return TOOL_OUTPUTS.af_get_balance.parse({
      currency: 'USD',
      balanceMinor: toMinor(usd.available_balance ?? usd.total_balance),
      observedAt: new Date().toISOString(),
    });
  }

  async listTransactions(_resourceId: string, fromDate: string, limit: number) {
    // PayPal searches at most 31 days at a time.
    const start = Date.parse(fromDate);
    const end = Math.min(Date.now(), start + 31 * 86_400_000);
    const query = new URLSearchParams({
      start_date: new Date(start).toISOString(),
      end_date: new Date(end).toISOString(),
      fields: 'transaction_info',
      page_size: String(limit),
    });
    const { transaction_details: details = [] } = await this.request<{ transaction_details?: { transaction_info: PayPalTransaction }[] }>(
      'GET',
      `/v1/reporting/transactions?${query}`,
    );
    return TOOL_OUTPUTS.af_list_transactions.parse({
      transactions: details
        .map((d) => d.transaction_info)
        .filter((tx) => tx.transaction_amount.currency_code === 'USD')
        .slice(0, limit)
        .map((tx) => ({
          transactionId: tx.transaction_id,
          amountMinor: toMinor(tx.transaction_amount),
          currency: 'USD',
          date: tx.transaction_initiation_date.slice(0, 10),
          description: labelUntrusted(tx.transaction_subject || tx.transaction_note || tx.transaction_event_code || 'transaction'),
        })),
    });
  }

  async execute(reservationId: string, call: TransferCall): Promise<AdapterResult> {
    const receiver = this.o.payees[call.payeeId];
    if (!receiver) return { state: 'failed', reasonCode: 'PAYEE_NOT_MAPPED' };
    if (call.currency !== 'USD') return { state: 'failed', reasonCode: 'CURRENCY_NOT_SUPPORTED' };
    let batchId: string;
    try {
      const created = await this.request<Batch>(
        'POST',
        '/v1/payments/payouts',
        payout(reservationId, reservationId, receiver, call.amountMinor),
        { 'paypal-request-id': reservationId },
      );
      batchId = created.batch_header.payout_batch_id;
    } catch (error) {
      if (error instanceof DuplicateError) return this.batch(error.batchId);
      if (error instanceof RejectedError) return { state: 'failed', reasonCode: error.message };
      throw error;
    }
    // Sent. From here on a failed lookup means "don't know yet", never "failed".
    try {
      return await this.batch(batchId);
    } catch {
      return { state: 'unknown', correlationId: batchId };
    }
  }

  async reconcile(reservationId: string): Promise<AdapterResult> {
    try {
      await this.request<Batch>('POST', '/v1/payments/payouts', payout(reservationId, FENCE_ITEM, 'nobody@example.com', 0));
    } catch (error) {
      if (error instanceof DuplicateError) return this.batch(error.batchId);
      throw error;
    }
    // Our $0 batch took the id: the payout was never made, and now can't be.
    return { state: 'failed', reasonCode: 'NOT_EXECUTED' };
  }
}

function payout(batchId: string, itemId: string, receiver: string, amountMinor: number) {
  return {
    sender_batch_header: { sender_batch_id: batchId, email_subject: 'You have a payment' },
    items: [
      {
        recipient_type: 'EMAIL',
        receiver,
        amount: { value: `${Math.floor(amountMinor / 100)}.${String(amountMinor % 100).padStart(2, '0')}`, currency: 'USD' },
        sender_item_id: itemId,
        note: 'kordn',
      },
    ],
  };
}

function outcome(batch: Batch): AdapterResult {
  const id = batch.batch_header.payout_batch_id;
  const item = batch.items?.[0];
  if (item?.payout_item.sender_item_id === FENCE_ITEM) return { state: 'failed', reasonCode: 'NOT_EXECUTED' };
  if (!item) {
    const status = batch.batch_header.batch_status;
    return ['DENIED', 'CANCELED'].includes(status) ? { state: 'failed', reasonCode: `paypal:${status.toLowerCase()}` } : { state: 'unknown', correlationId: id };
  }
  // UNCLAIMED: the money has left; the receiver has 30 days to claim it before PayPal returns it.
  // Counted as spent, so it stays against the limits.
  if (item.transaction_status === 'SUCCESS' || item.transaction_status === 'UNCLAIMED') {
    return { state: 'succeeded', receiptId: item.transaction_id || item.payout_item_id };
  }
  if (['PENDING', 'ONHOLD'].includes(item.transaction_status)) return { state: 'unknown', correlationId: id };
  return { state: 'failed', reasonCode: `paypal:${item.transaction_status.toLowerCase()}` };
}

/** The batch id PayPal links to when a sender_batch_id is already taken. Only the id is used, never the URL. */
function duplicateOf(error: PayPalError): string | undefined {
  const detail = error.details?.find((d) => d.field === 'SENDER_BATCH_ID' && /already exists/i.test(d.issue ?? ''));
  return detail?.link?.map((l) => /\/v1\/payments\/payouts\/([A-Z0-9]+)$/.exec(l.href ?? '')?.[1]).find(Boolean);
}

interface Money {
  value: string;
  currency_code?: string;
}

interface PayPalTransaction {
  transaction_id: string;
  transaction_amount: Required<Money>;
  transaction_initiation_date: string;
  transaction_event_code?: string;
  transaction_subject?: string;
  transaction_note?: string;
}

/** "-12.34" to -1234, without going through floating point. */
function toMinor(money: Money): number {
  const match = /^(-?)(\d+)(?:\.(\d{1,2}))?$/.exec(money.value);
  if (!match) throw new Error('paypal: bad amount');
  const minor = Number(match[2]) * 100 + Number((match[3] ?? '').padEnd(2, '0'));
  return match[1] ? -minor : minor;
}

/** PayPal refused the request outright (4xx): nothing was sent. */
class RejectedError extends Error {}

/** The sender_batch_id is taken: the payout (or our $0 batch) already exists. */
class DuplicateError extends Error {
  constructor(readonly batchId: string) {
    super('paypal: duplicate sender_batch_id');
  }
}
