import { DenyCode, parseToolCall, Policy, ToolName, TOOL_OUTPUTS } from './schema.js';
import type { AdapterResult, BankAdapter } from './schema.js';
import type { ActivityFilter, ApprovalResult, CallResult, Guardian as GuardianApi, OAuthAuditEvent, PendingApproval, PolicyUpdateResult } from './guardian-api.js';
import { ApprovalDecisionError, GuardianError, Ledger, PolicyVersionConflict } from './ledger.js';
import type { Reservation } from './ledger.js';

/** App-supplied text reaches the audit log, so it loses control characters and is cut short. */
export const cleanAppText = (text: string): string => Array.from(text.replace(/[\p{Cc}\p{Cf}]/gu, '')).slice(0, 100).join('');

export { GuardianError } from './ledger.js';

export class Guardian implements GuardianApi {
  constructor(readonly ledger: Ledger, private readonly adapter: BankAdapter, readonly agentId: string,
    private readonly timeoutMs = 10_000) {
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2 ** 31 - 1) throw new Error('invalid adapter timeout');
  }

  private async deadline<T>(operation: () => Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([Promise.resolve().then(operation), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new GuardianError('INTERNAL_UNAVAILABLE')), this.timeoutMs);
      })]);
    } finally { clearTimeout(timer); }
  }

  async handleCall(agentId: string, tool: unknown, args: unknown): Promise<CallResult> {
    try {
      if (agentId !== this.agentId) {
        this.ledger.recordDenied(this.agentId, 'UNKNOWN_ACTION');
        throw new GuardianError('UNKNOWN_ACTION');
      }
      if (this.ledger.getPolicy(agentId).revoked) {
        this.ledger.recordDenied(agentId, 'SESSION_REVOKED');
        throw new GuardianError('SESSION_REVOKED');
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
        const result = !admission.fresh || r.state === 'PENDING_APPROVAL' ? this.transferOutput(r) : await this.run(r.id);
        return { ok: true, result };
      }
      let result: unknown;
      switch (call.tool) {
        case 'af_get_balance': result = await this.deadline(() => this.adapter.getBalance(call.resourceId)); break;
        case 'af_list_transactions': {
          const output = TOOL_OUTPUTS.af_list_transactions.parse(await this.deadline(() =>
            this.adapter.listTransactions(call.resourceId, call.fromDate, call.limit)));
          if (output.transactions.length > call.limit || output.transactions.some((tx) => tx.date < call.fromDate)) {
            throw new GuardianError('INTERNAL_UNAVAILABLE');
          }
          result = output;
          break;
        }
        case 'af_get_transfer_status': {
          if (this.ledger.get(call.transferRef, agentId)?.state === 'UNKNOWN') await this.refreshUnknown(call.transferRef);
          const r = this.ledger.get(call.transferRef, agentId)!;
          result = { state: r.state, reasonCode: r.reasonCode, updatedAt: new Date(r.updatedMs).toISOString() };
          break;
        }
        default: throw new GuardianError('INVALID_ARGUMENTS');
      }
      const output = TOOL_OUTPUTS[call.tool].parse(result);
      this.ledger.transaction(() => this.ledger.event(agentId, 'read.executed', call));
      return { ok: true, result: output };
    } catch (error) {
      let code: DenyCode = 'INTERNAL_UNAVAILABLE';
      // Untrusted getters can throw arbitrary values, including proxies with throwing prototypes.
      try {
        if (error instanceof GuardianError) code = DenyCode.parse(error.code);
      } catch { /* Keep the safe internal-failure code. */ }
      if (code === 'INTERNAL_UNAVAILABLE') {
        try { this.ledger.recordDenied(this.agentId, code); }
        catch { /* Storage failure still denies the action. */ }
      }
      return { ok: false, error: { code, message: code } };
    }
  }

  private transferOutput(r: Reservation) {
    const state = r.state === 'SUCCEEDED' ? 'succeeded' : r.state === 'FAILED' ? 'failed' :
      r.state === 'PENDING_APPROVAL' ? 'pending_approval' : r.state === 'REJECTED' ? 'rejected' :
      r.state === 'EXPIRED' ? 'expired' : 'unknown';
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
    const r = this.ledger.transition(id, result.state === 'succeeded' ? 'SUCCEEDED' : result.state === 'failed' ? 'FAILED' : 'UNKNOWN',
      result.state === 'failed' ? 'ADAPTER_FAILED' : null);
    return this.transferOutput(r);
  }

  /** Called by the trusted launcher before serving requests; never resends uncertain actions. */
  async reconcile(): Promise<void> {
    for (const r of this.ledger.listByState(this.agentId, ['RESERVED', 'APPROVED', 'DISPATCHING', 'UNKNOWN'])) {
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
      if (this.ledger.get(r.id)?.state !== 'UNKNOWN') continue;
      this.ledger.transition(r.id, result.state === 'succeeded' ? 'SUCCEEDED' : 'FAILED',
        result.state === 'failed' ? 'ADAPTER_FAILED' : null, 'transfer.reconciled');
    }
    this.expirePending();
  }

  /**
   * Asks the adapter about transfers left UNKNOWN (a payout still processing, a lost reply) and
   * records a definite outcome. Safe while serving: it never touches DISPATCHING, so a call in
   * flight isn't raced, and "never executed" keeps the quota held; only reconcile() at startup
   * trusts that answer.
   */
  async refreshUnknown(id?: string): Promise<void> {
    for (const r of this.ledger.listByState(this.agentId, ['UNKNOWN'])) {
      if (id !== undefined && r.id !== id) continue;
      let result: AdapterResult;
      try { result = this.outcome(await this.deadline(() => this.adapter.reconcile(r.id))); }
      catch { continue; }
      if (result.state === 'unknown' || (result.state === 'failed' && result.reasonCode === 'NOT_EXECUTED')) continue;
      try {
        this.ledger.transition(r.id, result.state === 'succeeded' ? 'SUCCEEDED' : 'FAILED',
          result.state === 'failed' ? 'ADAPTER_FAILED' : null, 'transfer.reconciled');
      } catch { /* Settled meanwhile by another refresh. */ }
    }
  }

  private expirePending(): void {
    for (const r of this.ledger.listByState(this.agentId, ['PENDING_APPROVAL'], this.ledger.clock.nowMs())) {
      this.ledger.transition(r.id, 'EXPIRED', 'APPROVAL_EXPIRED');
    }
  }

  async listPending(): Promise<PendingApproval[]> {
    this.expirePending();
    return this.ledger.listByState(this.agentId, ['PENDING_APPROVAL']).map((r) => ({
      reservationId: r.id, agentId: r.agentId, resourceId: r.call.resourceId, payeeId: r.call.payeeId,
      amountMinor: r.call.amountMinor, currency: r.call.currency, policyVersion: r.policyVersion,
      digest: r.requestHash, nonce: r.nonce!, expiresAt: new Date(r.expiresMs).toISOString(),
    }));
  }

  async approve(reservationId: string, digest: string, nonce: string): Promise<ApprovalResult> {
    try {
      this.ledger.decide(reservationId, nonce, digest, true, this.agentId);
      await this.run(reservationId);
      return { ok: true };
    } catch (error) {
      if (error instanceof GuardianError || error instanceof ApprovalDecisionError) return { ok: false, code: error.code };
      throw error;
    }
  }

  async reject(reservationId: string, nonce: string): Promise<ApprovalResult> {
    try {
      this.ledger.decide(reservationId, nonce, null, false, this.agentId);
      return { ok: true };
    } catch (error) {
      if (error instanceof GuardianError || error instanceof ApprovalDecisionError) return { ok: false, code: error.code };
      throw error;
    }
  }

  async revoke(agentId: string = this.agentId): Promise<void> {
    if (agentId === this.agentId) this.ledger.revoke(agentId);
  }

  async isRevoked(agentId: string): Promise<boolean> {
    return agentId === this.agentId && this.ledger.getPolicy(agentId).revoked;
  }

  async getPolicy() {
    const { policy, version } = this.ledger.getPolicy(this.agentId);
    return { policy, version };
  }

  async updatePolicy(input: unknown, expectedVersion: number): Promise<PolicyUpdateResult> {
    if (this.ledger.getPolicy(this.agentId).version !== expectedVersion) return { ok: false, code: 'VERSION_CONFLICT' };
    const policy = Policy.safeParse(input);
    if (!policy.success || policy.data.agentId !== this.agentId) return { ok: false, code: 'INVALID_POLICY' };
    try {
      const { version } = this.ledger.updatePolicy(policy.data, expectedVersion);
      return { ok: true, version };
    } catch (error) {
      if (error instanceof PolicyVersionConflict) return { ok: false, code: 'VERSION_CONFLICT' };
      throw error;
    }
  }

  async listActivity(filter: ActivityFilter = {}) {
    if (!Number.isInteger(filter.limit ?? 100) || (filter.limit ?? 100) < 1) throw new RangeError('invalid activity limit');
    return this.ledger.audit.list({ ...filter, agentId: this.agentId });
  }

  async recordRefusedConnection(refused = 1): Promise<void> {
    const count = Number.isSafeInteger(refused) && refused > 0 ? refused : 1;
    try {
      this.ledger.transaction(() => this.ledger.event(this.agentId, 'action.attempted', null, null, null, null, null,
        { reason: 'connection_limit', refused: count }));
    } catch { /* A failed audit writer cannot make the socket server accept the refused connection. */ }
  }

  async recordOAuthEvent(event: OAuthAuditEvent, app: { client: string; redirectHost: string }): Promise<void> {
    try {
      const metadata = { client: cleanAppText(app.client), redirectHost: cleanAppText(app.redirectHost) };
      this.ledger.transaction(() => this.ledger.event(this.agentId, event, null, null, null, null, null, metadata));
    } catch { /* A failed audit writer must not break the OAuth flow it describes. */ }
  }
}
