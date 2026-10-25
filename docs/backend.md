# Backend contract and review (#1–#8)

The backend implements the four tools in `src/schema.ts`. It assumes the model,
tool arguments, and transaction descriptions are hostile. Authorization is a pure
function; SQLite admission and the guardian enforce its decision outside the model.
The shared schema is unchanged.

## Contract review (#1)

Reviewed `README.md`, `docs/threat-model.md`, the design document (especially
§5–8, §10.3, and §11), all shared schemas, hashing, fixtures, and existing tests.
The separate MCP, admin, and sandbox issues consume this backend; this change
does not implement those components or claim OS containment.

Implementation decisions that integrators need to know:

- Unknown resources and identity mismatches use the existing `INVALID_ARGUMENTS`
  code. No new deny code or shared schema change is needed.
- Status references have no resource or identity field. The ledger looks them up
  under the trusted agent ID and checks their resource before returning status.
- Design §6.4 distinguishes status polling from financial reads. Status polling
  has a separate limit of 60 accepted polls per rolling minute per agent and
  returns `RATE_LIMITED` above it. It does not consume `reads.maxCalls` or require
  `reads.allow`. Revocation still blocks it. A configurable polling limit would
  require a separately reviewed policy-schema change.
- Rolling windows exclude the exact lower endpoint: `(now - window, now]`.
  Completed transfers age out from their recorded completion (or reconciliation)
  time, never before their admission time; unresolved reservations continue holding quota,
  including beyond their original window. `UNKNOWN` never expires on a timer.
- Approval binds the canonical call, reservation ID, policy version, and expiry
  in its digest. A policy edit invalidates an old approval, including a loosening
  of limits. Rejection, expiry, or definitive failure releases quota; the same
  idempotency key continues returning that terminal reservation.
- Revocation is permanent for an agent ID. Editing its policy does not reactivate
  it. An already dispatching operation may still complete; revocation cannot undo
  an external action.
- Audit events and financial state commit together. A separate tail checkpoint
  detects tail deletion as well as gaps, content changes, and reordered rows.
  This is local tamper evidence, not protection against a privileged host owner
  who can rewrite both the log and its checkpoint.

No changes to `src/schema.ts` are proposed here. The above decisions and API
are ready for review with the MCP/admin contributor; no agreement or review by
another contributor is implied.

## Starting the trusted backend

Requires patched Node.js 24.22.1+ (24.x) or 26.12.1+ (26.x).
Database constructors require a private parent directory
(mode `0700`), create/restrict database files to mode `0600`, and reject file
symlinks and hard links. SQLite WAL files stay inside the private directory. Use
persistent paths in that directory. `MockBankAdapter` requires an explicit path;
use `':memory:'` explicitly only for disposable tests. The bank
database is deliberately separate from the guardian's policy and audit database.
An in-memory bank is suitable only for disposable unit tests.

```ts
import { Ledger } from './ledger.js';
import { Guardian } from './guardian.js';
import { MockBankAdapter } from './mock-bank.js';
import { Policy } from './schema.js';

const policy = Policy.parse(configuredPolicy);
const ledger = new Ledger('/private/kordn/ledger.sqlite');
// Provision once, through trusted setup. Do not reset policy on each restart.
ledger.updatePolicy(policy, 0);
const bank = new MockBankAdapter('/private/kordn/bank.sqlite');
const guardian = new Guardian(ledger, bank, policy.agentId);
await guardian.reconcile();
```

The setup call uses `expectedVersion = 0` only when the agent has no policy.
On subsequent starts, load the stored policy with `ledger.getPolicy(agentId)`.
Call `reconcile()` before exposing an in-process guardian to new calls. The Unix
socket server does this automatically before listening.

## Agent and admin APIs (#6)

`Guardian` is scoped to one launcher-selected agent. Its methods are:

| Method | Result |
| --- | --- |
| `handleCall(agentId, tool, args)` | Promise of a validated tool output; agent ID must match the launcher-bound ID |
| `listPending()` | Pending `Reservation[]`, including canonical call, digest, expiry, and private approval nonce |
| `approve(reservationId, digest, nonce)` | Promise of a transfer output after revalidation and execution |
| `reject(reservationId, nonce)` | Updated rejected reservation |
| `revoke(agentId)` | Synchronously persists revocation and rejects unsent reservations and pending approvals |
| `getPolicy()` | `{ policy, version, revoked }` |
| `updatePolicy(policy, expectedVersion)` | The new `{ policy, version, revoked }`; fails on a stale version |
| `listActivity({ event?, limit? })` | Newest-first `AuditEvent[]` for this agent; defaults to 100, capped at 1,000 |
| `reconcile()` | Resolves uncertain outcomes against the adapter without resending them |

Only the trusted admin integration may call administrative methods. It owns
authentication, sessions, CSRF protection, and Origin checks (issues #14–#15).
Never put `listPending()` or its nonce on the agent's tool surface. Agent proposal
outputs contain only state, transfer reference, and reason code.

Policy denials and invalid calls throw `GuardianError` with a schema-defined
`code`. Adapter/DB failures fail closed. A transfer whose dispatch outcome is
uncertain returns `state: 'unknown'`; its quota remains held. Definite adapter
failure returns `state: 'failed'`. Adapter-specific failure strings that are not
`DenyCode` values map to `INTERNAL_UNAVAILABLE` in stored public reasons.

## Unix socket integration

```ts
import { serveGuardian, callGuardian } from './socket.js';

const server = await serveGuardian(guardian, '/private/kordn/agent.sock');
// In the untrusted MCP shim, forward the original tool and arguments:
const output = await callGuardian('/mounted/agent.sock', tool, args);
```

The parent directory must be private (mode `0700`); the socket is mode `0600`.
The trusted launcher must arrange socket access for the intended agent UID and
mount only that agent's socket into its sandbox. Identity is bound to this server
instance; no payload identity is accepted. The server never replaces an existing
socket. The launcher must clean up a stale socket only after confirming that its
old guardian has stopped.

The protocol is newline-delimited JSON using `SocketRequest` and `SocketResponse`.
Frames and buffered input are capped at `MAX_FRAME_BYTES`; idle connections time
out. Each server allows 64 simultaneous connections. Incomplete frames have an
absolute 30-second deadline, and client calls have an absolute response deadline;
trickling bytes does not extend either deadline. Invalid frames and unknown tools
cannot reach the bank. A missing, killed,
or unresponsive guardian returns an explicit error; there is no direct adapter
fallback. This socket implementation does not itself establish Contain mode.

## Recovery and adapter faults (#7–#8)

The adapter persists deduplication and account changes atomically by reservation
ID. Switchable `bank.faults` are `delayMs`, `reject`, and `responseLost`. A lost
response returns `unknown`; reconciliation returns the durable bank outcome.
Delayed sends persist an intent first, so concurrent reconciliation cannot report
non-execution while the original operation might still apply.

On recovery, `DISPATCHING` becomes `UNKNOWN`. Reconciliation resolves it only
with a definite adapter result. Unsent `RESERVED`/`APPROVED` actions remain held
until the adapter proves non-execution, then become `REJECTED`; they are never
automatically resent. Expired pending approvals become `EXPIRED`.

If the bank process itself dies after persisting intent but before recording an
outcome, that intent stays unknown and holds quota. This conservative case needs
trusted operator investigation; the adapter does not guess or retry it. Restore
the guardian and bank databases together; discarding the bank database discards
its deduplication evidence.

## Validation

```sh
npm ci
npm run typecheck
npm test
npm run test:concurrency
```

The test command builds the real JavaScript used by subprocess tests. The stress
command runs 50 consecutive rounds. Each round checks 1,000 concurrent proposals
against count and cumulative limits separately, two real `SIGKILL` checkpoints
(reserved-before-send and applied-with-response-lost), and guardian-process death.
Unit/integration tests also cover policy precedence and boundaries, sliding read
windows, duplicate/conflicting keys, audit tampering and write failures, approval
expiry/digest/nonce, policy changes, revocation, adapter timeouts, and socket framing.

These are backend checks. The Linux sandbox, real MCP clients, admin authentication,
and the full T01–T20 integration matrix belong to the remaining integration work.
