import { DenyCode, parseToolCall, ToolName, TOOL_OUTPUTS } from './schema.js';
import type { AdapterResult, AuditEvent, BankAdapter, Policy } from './schema.js';
import { GuardianError, Ledger } from './ledger.js';
import type { Reservation } from './ledger.js';

export { GuardianError } from './ledger.js';

export class Guardian {
  constructor(readonly ledger: Ledger, private readonly adapter: BankAdapter, readonly agentId: string,
    private readonly timeoutMs = 10_000) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) throw new Error('invalid adapter timeout');
  }

  private async deadline<T>(operation: () => Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([Promise.resolve().then(operation), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new GuardianError('INTERNAL_UNAVAILABLE', 'adapter timed out')), this.timeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }

  async handleCall(agentId: string, tool: unknown, args: unknown): Promise<unknown> {
    try {
      if (agentId !== this.agentId) {
        this.ledger.recordDenied(this.agentId, 'INVALID_ARGUMENTS');
        throw new GuardianError('INVALID_ARGUMENTS');
      }
      const call = parseToolCall(tool, args);
      if (!call) {
        const code = ToolName.safeParse(tool).success ? 'INVALID_ARGUMENTS' : 'UNKNOWN_ACTION';
        this.ledger.recordDenied(agentId, code);
        throw new GuardianError(code);
      }
      this.expirePending();
      const admission = this.ledger.admit(agentId, call);
      if (admission.kind === 'transfer') {
        const r = admission.reservation;
        if (!admission.fresh || r.state === 'PENDING_APPROVAL') return this.transferOutput(r);
        return await this.run(r.id);
      }
      let result: unknown;
      switch (call.tool) {
        case 'af_get_balance': result = await this.deadline(() => this.adapter.getBalance(call.resourceId)); break;
        case 'af_list_transactions': {
          const output = TOOL_OUTPUTS.af_list_transactions.parse(await this.deadline(() =>
            this.adapter.listTransactions(call.resourceId, call.fromDate, call.limit)));
          if (output.transactions.length > call.limit || output.transactions.some((tx) => tx.date < call.fromDate)) {
            throw new GuardianError('INTERNAL_UNAVAILABLE', 'adapter exceeded requested read bounds');
          }
          result = output;
          break;
        }
        case 'af_get_transfer_status': {
          const r = this.ledger.get(call.transferRef, agentId)!;
          result = { state: r.state, reasonCode: r.reasonCode, updatedAt: new Date(r.updatedMs).toISOString() };
          break;
        }
        default: throw new GuardianError('INVALID_ARGUMENTS');
      }
      const output = TOOL_OUTPUTS[call.tool].parse(result);
      this.ledger.transaction(() => this.ledger.event(agentId, 'read.executed', call));
      return output;
    } catch (error) {
      if (error instanceof GuardianError) throw error;
      throw new GuardianError('INTERNAL_UNAVAILABLE');
    }
  }

  private transferOutput(r: Reservation) {
    const state = r.state === 'SUCCEEDED' ? 'succeeded' : r.state === 'FAILED' ? 'failed' :
      ['PENDING_APPROVAL', 'APPROVED'].includes(r.state) ? 'pending_approval' :
      ['REJECTED', 'EXPIRED'].includes(r.state) ? 'denied' : 'unknown';
    return TOOL_OUTPUTS.af_propose_transfer.parse({ state, transferRef: r.id, reasonCode: r.reasonCode });
  }

  private outcome(result: AdapterResult): AdapterResult {
    if (!result || !['succeeded', 'failed', 'unknown'].includes(result.state)) throw new Error('invalid adapter result');
    if ((result.state === 'succeeded' && (typeof result.receiptId !== 'string' || !result.receiptId)) ||
        (result.state === 'failed' && (typeof result.reasonCode !== 'string' || !result.reasonCode)) ||
        (result.state === 'unknown' && (typeof result.correlationId !== 'string' || !result.correlationId))) throw new Error('invalid adapter result');
    return result;
  }

  private async run(id: string) {
    const reservation = this.ledger.dispatch(id);
    let result: AdapterResult;
    try { result = this.outcome(await this.deadline(() => this.adapter.execute(id, reservation.call))); }
    catch { result = { state: 'unknown', correlationId: id }; }
    const current = this.ledger.get(id)!;
    if (current.state === 'SUCCEEDED' || current.state === 'FAILED') return this.transferOutput(current);
    if (current.state === 'UNKNOWN' && result.state === 'unknown') return this.transferOutput(current);
    const reason = result.state === 'failed' ? DenyCode.safeParse(result.reasonCode) : null;
    const r = this.ledger.transition(id, result.state === 'succeeded' ? 'SUCCEEDED' : result.state === 'failed' ? 'FAILED' : 'UNKNOWN',
      result.state === 'failed' ? reason?.success ? reason.data : 'INTERNAL_UNAVAILABLE' : null);
    return this.transferOutput(r);
  }

  /** Startup reconciliation never resends an uncertain action. */
  async reconcile(): Promise<void> {
    for (const r of this.ledger.list(this.agentId)) {
      if (!['RESERVED', 'APPROVED', 'DISPATCHING', 'UNKNOWN'].includes(r.state)) continue;
      if (r.state === 'DISPATCHING') this.ledger.transition(r.id, 'UNKNOWN');
      let result: AdapterResult;
      try { result = this.outcome(await this.deadline(() => this.adapter.reconcile(r.id))); }
      catch { continue; }
      if (result.state === 'unknown') continue;
      if (r.state === 'RESERVED' || r.state === 'APPROVED') {
        if (result.state === 'failed' && this.ledger.get(r.id)?.state === r.state) {
          this.ledger.transition(r.id, 'REJECTED', null, 'transfer.reconciled');
        }
        continue;
      }
      // Another reconciliation may have completed while awaiting the adapter.
      if (this.ledger.get(r.id)?.state !== 'UNKNOWN') continue;
      this.ledger.transition(r.id, result.state === 'succeeded' ? 'SUCCEEDED' : 'FAILED',
        result.state === 'failed' ? 'INTERNAL_UNAVAILABLE' : null, 'transfer.reconciled');
    }
    this.expirePending();
  }

  private expirePending(): void {
    for (const r of this.ledger.list(this.agentId)) {
      if (r.state === 'PENDING_APPROVAL' && r.expiresMs <= this.ledger.clock.nowMs()) {
        this.ledger.transition(r.id, 'EXPIRED', 'APPROVAL_EXPIRED');
      }
    }
  }

  listPending(): Reservation[] {
    this.expirePending();
    return this.ledger.list(this.agentId).filter((r) => r.state === 'PENDING_APPROVAL');
  }

  async approve(reservationId: string, digest: string, nonce: string) {
    this.ledger.decide(reservationId, nonce, digest, true, this.agentId);
    try { return await this.run(reservationId); }
    catch (error) {
      if (error instanceof GuardianError) throw error;
      throw new GuardianError('INTERNAL_UNAVAILABLE');
    }
  }

  reject(reservationId: string, nonce: string) {
    return this.ledger.decide(reservationId, nonce, null, false, this.agentId);
  }

  revoke(agentId: string = this.agentId): void {
    if (agentId !== this.agentId) throw new GuardianError('INVALID_ARGUMENTS');
    this.ledger.revoke(agentId);
  }

  getPolicy() { return this.ledger.getPolicy(this.agentId); }

  updatePolicy(policy: Policy, expectedVersion: number) {
    if (policy.agentId !== this.agentId) throw new GuardianError('INVALID_ARGUMENTS');
    return this.ledger.updatePolicy(policy, expectedVersion);
  }

  listActivity(filter: { event?: AuditEvent['event']; limit?: number } = {}) {
    return this.ledger.audit.list({ ...filter, agentId: this.agentId });
  }
}
