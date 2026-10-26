# Backend contract (#1–#8)

The real backend implements the shared `Guardian` interface in `src/guardian-api.ts`
and the four tool schemas in `src/schema.ts`. It assumes hostile tool arguments and
transaction descriptions. Pure policy evaluation, atomic SQLite admission, and the
trusted adapter enforce decisions outside the model. The admin UI and Unix-socket
server from main can consume this implementation directly.

## Trusted setup

Use patched Node.js 24.22.1+ (24.x) or 26.12.1+ (26.x). Database constructors require
private parent directories (`0700`), restrict files to `0600`, and reject symlinks
and hard links. Keep SQLite WAL files in that directory. Use separate persistent
paths for the guardian and bank; `:memory:` is only for disposable tests.

```ts
import { Ledger } from './ledger.js';
import { Guardian } from './guardian.js';
import { MockBankAdapter } from './mock-bank.js';
import { Policy } from './schema.js';
import { serveGuardianSocket } from './guardian-socket.js';
import { startAdminServer } from './admin/server.js';

const policy = Policy.parse(configuredPolicy);
const ledger = new Ledger('/private/kordn/ledger.sqlite');
ledger.updatePolicy(policy, 0); // Provision once; do not reset policy on restart.
const bank = new MockBankAdapter('/private/kordn/bank.sqlite');
const guardian = new Guardian(ledger, bank, policy.agentId);
await guardian.reconcile(); // Before serving requests, including after a restart.
const server = await serveGuardianSocket(guardian, policy.agentId, '/private/kordn/agent.sock');
// The launcher must set the socket's ownership/access before exposing it to the agent.
const admin = await startAdminServer({ guardian, agentId: policy.agentId, mode: 'guard' });
```

Use `expectedVersion = 0` only when no policy exists. On restart, load the stored
policy with `ledger.getPolicy(agentId)` instead. Socket serving does not perform
reconciliation automatically. The trusted launcher must call it before listening;
it may also arrange periodic reconciliation so new unknown outcomes need not wait
for a restart. Close the socket/admin servers before closing the ledger and bank.

## Agent and admin methods

All shared interface methods return promises. `handleCall(agentId, tool, args)`
never rejects: it returns `{ ok: true, result }` or a safe `{ ok: false, error }`.
Unknown tools, invalid arguments, policy denials, and internal failures use the
error branch, never a `state: 'denied'` result. Identity mismatch is `UNKNOWN_ACTION`.
`revoke` for another agent is a no-op; `isRevoked` for another agent returns false.

Proposal results use `pending_approval`, `succeeded`, `failed`, or `unknown`.
An idempotent retry can report the earlier `rejected` or `expired` outcome.
`APPROVED`/`DISPATCHING` report unknown until execution completes. Every bank-side
failure string maps to `ADAPTER_FAILED`; raw adapter text never reaches the agent.
Unknown execution outcomes keep quota and are not retried automatically.

`listPending()` returns copied `PendingApproval[]` with flat canonical details,
`reservationId`, `digest`, `nonce`, and `expiresAt`. The digest is `requestHash` of
the canonical transfer, as specified by the shared API. Approval additionally
checks the stored reservation's identity, policy version, expiry, and one-use nonce.
New approvals use `APPROVAL_TTL_SEC` (900 seconds). Approval/rejection return the
shared `ApprovalResult`, including `STALE_DIGEST`, `BAD_NONCE`, `NOT_PENDING`, or a
policy denial. Approval acceptance does not promise that the bank will succeed.

`getPolicy()` returns `{ policy, version }`; use `isRevoked(agentId)` for revocation.
`updatePolicy(unknown, expectedVersion)` returns the shared `PolicyUpdateResult`,
with `VERSION_CONFLICT` or `INVALID_POLICY` for expected input failures. Internal
admin-method failures may reject. `listActivity({ events?, limit? })` is newest
first, defaults to 100, caps at 1,000, and rejects invalid limits. Returned policy,
approval, and activity objects are copies. `recordRefusedConnection(count)` logs
aggregated socket refusals and never rejects if audit storage is unavailable.

Only the authenticated admin integration may call administrative methods. Never
expose pending approval nonces or administrative methods as agent tools. The
merged admin UI supplies login/session, Origin, CSRF, CSP, and escaping checks;
the integration tests exercise it against the real guardian.

## Accounting and recovery

- Admission and evidence commit in one `BEGIN IMMEDIATE` transaction. Dispatch
  re-checks policy and limits under that writer lock before calling the adapter.
- Completed transfers age out from the later of admission and recorded completion
  or reconciliation. Rolling windows exclude the exact lower endpoint. Unresolved
  reservations keep quota beyond their original window; `UNKNOWN` never times out.
- Status references are looked up under the bound agent and current resource.
  Status polling has its own limit of 60 accepted calls per rolling minute and
  does not consume financial reads or require `reads.allow`. Revocation blocks it.
- Expiry, pending-list, revoke, and reconciliation queries filter states in SQL
  before decoding. A supporting index avoids loading terminal history on each call.
- Policy changes invalidate earlier approvals. Revocation is permanent for an
  agent ID and rejects unsent reservations; it cannot undo an in-flight operation.
- The bank persists intents before delay/send and applies account changes and
  deduplication atomically by reservation ID. Faults are `delayMs`, `reject`, and
  `responseLost`. Memos use `labelUntrusted`, independent of fixture answer keys;
  synthetic history dates follow the injected clock.
- Recovery changes `DISPATCHING` to `UNKNOWN` and queries the adapter without a
  resend. Unsent reservations are rejected only after proof of non-execution.
  A bank process dying with an intent and no outcome needs trusted investigation.
- Audit events and state commit together. Hash chaining and a tail checkpoint
  detect edits, deletion, and reordering; they do not resist a privileged host
  owner rewriting both. Restore both databases consistently with SQLite-aware
  backups, including committed WAL state. Sustained audit growth still needs a
  storage budget and archival policy before hostile long-lived deployment.

## Socket and containment boundary

Use `serveGuardianSocket` from `src/guardian-socket.ts`; there is one server
implementation. It binds identity to the supplied agent ID and socket endpoint,
not payload fields. The trusted launcher owns the private socket directory,
permissions, namespace UID/GID mapping, and cleanup of a confirmed stale socket.
A same-host-UID fixture can use `0600`. Container UID 10001 does not automatically
map to the host socket owner: verify ownership/group access inside the actual
rootless sandbox and deny access to other agents. Never use world-writable access
as a substitute. This Linux integration gate remains pending in #11/#12.

The protocol uses newline-delimited `SocketRequest`/`SocketResponse`. Invalid or
oversized frames close the connection before reaching the guardian. The shared
server bounds frames, queued calls, unread responses, idle time, and connections
(default 32). Its incomplete-frame deadline defaults to 30 seconds and is not
extended by trickling bytes. The client helper in `src/guardian-client.ts` forwards
raw tool arguments, uses an absolute response deadline, and returns the tool result
or throws a safe coded error. It never falls back to the bank.

## Validation

```sh
npm ci
npm run typecheck
npm test
npm run test:concurrency
```

Tests cover the pure policy boundaries, rolling windows, duplicate/conflicting
keys, audit tampering/write failures, approval binding and races, revocation,
read-only storage, output validation, socket framing/backpressure, and the real
backend through the authenticated admin UI and shared socket server. The stress
command runs 50 rounds, with 1,000 concurrent proposals per count/total profile,
real SIGKILL checkpoints, reopened databases, and a killed guardian process.

These checks do not establish Linux containment or interoperability with real MCP
clients. The single active guardian writer and trusted launcher remain deployment
assumptions; SIGKILL testing is not a power-loss or disk-full test.
