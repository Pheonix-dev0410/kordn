# Backend security review — 2026-10-26

## Scope and verdict

Reviewed the backend for issues #1–#8 against `docs/threat-model.md`, the design
document, and the shared contract. Assumed the documented single trusted guardian
writer, one local mock bank, and a hostile agent capable of concurrent malformed
requests. The MCP server, admin web application, and OS sandbox are not yet part
of this implementation.

The initial 72 tests passed, but new probes reproduced four defects. Those defects
are fixed and covered by regression tests. This is suitable for continued mock-bank
development. It is not evidence of a vulnerability-free system or a completed
Contain security boundary.

## Confirmed defects fixed

### 1. High: late completion bypassed rolling limits

`src/ledger.ts`, `test/security.test.ts`.

The usage query aged successful transfers from their reservation creation time.
If execution completed after the original window, the newly completed transfer
immediately disappeared from usage. With a one-second window and a $50 total
limit, advancing the injected clock while the first $50 call was in flight allowed
another $50 call immediately after the first completed. The same case bypassed
the count limit.

Successful transfers now count from the later of admission and recorded completion
or reconciliation. Unknown outcomes still hold quota without a time expiry.
Regression tests cover count and total limits, both ordinary completion and lost
response/reconciliation, and release at the new window boundary.

### 2. Medium: database constructors accepted public directories

`src/database.ts`, `src/ledger.ts`, `src/mock-bank.ts`, `test/security.test.ts`.

Both constructors previously relied on the caller to choose a host-only directory.
They accepted a `0755` directory, allowing ordinary file-creation defaults to expose
policy, audit data, and stored approval nonces to other local users. Actual access
depended on ancestor directory permissions and the process umask.

Both now require a private parent directory, create/restrict database files to
`0600`, and reject symlink and hard-linked database files. Tests check directory
rejection and permissions on the database, WAL, and shared-memory files. The mock
adapter now requires an explicit database path; disposable tests explicitly choose
`:memory:` so restart safety is not silently disabled by a default.

### 3. Medium: response timeout could be extended by trickling bytes

`src/socket.ts`, `test/socket.test.ts`.

The client used a socket idle timeout as its request deadline. A peer sending a
space every five milliseconds kept a twenty-millisecond call alive until the peer
closed at roughly three hundred milliseconds. This could keep requests pending
far beyond the configured deadline.

Client calls now use an absolute timer that is cleared on completion or failure.
The regression test uses an actual Unix socket and a trickling peer. The server
also has an absolute thirty-second deadline for incomplete frames and a sixty-four
connection limit. Tests exercise both limits, including a rejected sixty-fifth
connection and partial frames that keep arriving before the idle timeout.

### 4. Medium: concurrent reconciliation produced an invalid UNKNOWN transition

`src/guardian.ts`, `test/security.test.ts`.

Reconciliation could change an in-flight reservation from `DISPATCHING` to
`UNKNOWN`. If execution then also returned unknown, the guardian attempted
`UNKNOWN -> UNKNOWN`, which the shared state machine correctly rejects. The caller
received `INVALID_ARGUMENTS` instead of the required unknown transfer output.

The execution path now returns the existing unknown result in this case. It still
retains quota. A regression test explicitly interleaves execution and reconciliation.

## Additional adversarial checks

- Malformed payloads, SQL-like payee strings, unknown resources, `__proto__`, and
  forged identity/approval fields do not reach the adapter or become raw audit text.
- Two simultaneous approvals sharing a nonce produce exactly one transfer.
- An actual read-only SQLite database fails closed before adapter execution.
- Audit insertion failure after the bank applies a transfer leaves the durable
  reservation holding quota; reconciliation resolves it without a second send.
- Existing checks cover hash-chain edits/deletion/reordering/replacement, stale
  policy versions, expired/replayed approvals, revocation, adapter delays and lost
  responses, output validation, idempotency conflicts, and guardian death.

## Validation evidence

Platform: macOS (`Darwin arm64`).

- Clean `npm ci`: passed, with no dependency changes beyond the declared Node range.
- Source and test TypeScript checks: passed.
- Node 24.22.1: 86 tests passed across 9 files. Its embedded SQLite is 3.53.4 and
  OpenSSL is 3.5.9.
- Node 26.12.1: the same 86 tests passed.
- Node 24 stress command: 250 checks passed across 50 consecutive rounds. This
  includes 100,000 proposals across count/total profiles, 100 reservation/response-loss
  SIGKILL checkpoints, and 50 guardian-process kills. Recovery reopens both databases.
- `npm audit`: zero known npm dependency advisories at the time of the check.
- Graphify's local code index was refreshed; local tool files remain ignored.

Node versions were checked against the official
[October 2026 security release](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases).
The declared supported ranges now start at Node 24.22.1 and 26.12.1. The embedded
SQLite release was compared with its [official release history](https://sqlite.org/changes.html).
An npm audit does not cover every runtime vulnerability or prove application safety.

## Remaining risk and release blockers

### Sustained request floods can exhaust audit storage

Every rejected tool attempt appends evidence. A bounded probe of 2,000 unknown-tool
requests produced 4,000 new audit rows, no transfers, and a valid chain. There is no
general per-agent attempt-rate limiter, storage quota, or archival mechanism yet.
Connection and frame limits bound individual socket resource use, but not cumulative
disk use. Continued flooding can fill the disk and stop the guardian from serving
legitimate requests. Database/audit failure denies new actions rather than bypassing
policy; that preserves authorization, not availability.

Before hostile long-lived deployment, add general admission throttling and a storage
budget with explicit operational behavior. Audit archival must preserve a trusted
chain checkpoint; deleting audit rows or disabling evidence when the disk fills
would weaken the security contract. This remains unresolved by this review.

### Full system security is not established

- Linux rootless sandbox isolation, socket mount/UID access, network denial, and
  absence of DB/admin mounts still need the actual Linux integration matrix.
- MCP clients, HTTP bearer authentication, and the admin application's session,
  Origin, CSRF, CSP, and escaping behavior are not implemented/tested here.
- The launcher must run a single active guardian writer. Cross-process ownership
  and deployment orchestration are assumptions, not enforced by SQLite's transaction
  lock between calls. Do not run startup reconciliation alongside a different live
  guardian dispatching against the same bank/ledger.
- Same-UID host processes and privileged host compromise are not isolated by socket
  mode bits. Endpoint-bound identity relies on the launcher exposing only the intended
  agent socket to its sandbox.
- A bank process that dies with a durable intent but no outcome remains unknown
  until trusted investigation. Both databases must be restored consistently using
  SQLite-aware backups that include committed WAL state.
- Power-loss durability, filesystem failure, disk-full operation, arbitrary binary
  database corruption, Windows behavior, and independent penetration testing were
  not exercised. SIGKILL tests are not power-loss tests.

No changes were pushed, merged, or made to `main` during this review.
