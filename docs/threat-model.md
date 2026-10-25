# Threat model (v0.1)

Source: design doc §1.3, §2. This file is the reviewed, in-repo version of that boundary. Changes to it need review from two maintainers.

## Allowed claim

For the supported local setup, guarded mock-bank actions cannot execute outside configured rules, assuming the trusted daemon and OS isolation remain uncompromised.

We do **not** claim "all AI agents are secure", "all unauthorized transfers are prevented", or "an MCP plugin alone stops rogue agents".

## Adversary

The model is fully adversarial. It can:

- issue arbitrary calls to allowed tools with arbitrary arguments,
- split transactions, repeat calls, and run requests concurrently,
- plant attack text in transaction descriptions and act on it,
- run arbitrary code inside its container and control any file writable to it,
- try to reach unapproved resources (mock bank, admin UI, policy DB, Internet).

Denials are made by the guardian, never by asking the model to be careful.

## Trust classes

| Class | Components |
|---|---|
| **Untrusted** | agent-runner, model output, retrieved pages/memos, tool arguments, mcp-shim, every process inside the sandbox |
| **Trusted** | guardian, policy DB, counter ledger, adapter-mock, admin-ui, launcher |
| **External** (assumed) | Linux kernel, rootless container runtime, filesystem permissions |
| **Out of scope** | root compromise, malicious host admin, kernel escape, compromised guardian binary, a user deliberately bypassing the sandbox, other OS users with root |

## Invariants

- **INV-01** Every guarded side effect passes guardian authorization and reservation before adapter execution.
- **INV-02** Unrecognized actions, schemas, currencies, resources and payees fail closed.
- **INV-03** Active reservations + completed actions in a rolling window stay at or under every budget.
- **INV-04** The agent cannot reach the mock-bank backend or admin APIs except through the guarded channel.
- **INV-05** Policy changes only via the trusted local admin channel; revocation wins over cached grants.
- **INV-06** Ambiguous execution outcomes keep their reservations until a trusted adapter resolves them.
- **INV-07** The audit trail distinguishes attempted, approved, executed, rejected and unknown events.

## Attacks and required responses

| Attack | Required response | Test |
|---|---|---|
| "Ignore rules" injected in a memo | Rendered as untrusted data; policy rejects regardless of text | T08 |
| Transfer to a new payee | `UNAPPROVED_PAYEE` even below the ceiling | T07 |
| Split $500 into $50s | Rolling count/total reject the excess | T05, T06 |
| 100 / 1,000 simultaneous requests | Atomic ledger transaction serializes updates | T12 |
| Same idempotency key, different body | `IDEMPOTENCY_CONFLICT`, never re-executes | T11 |
| Raw TCP to the mock bank | No network in sandbox, no bank socket mounted | T17 |
| Read guardian DB / approval token | Host-only paths, not mounted | T18 |
| Kill guardian mid-action | No bypass; outcome UNKNOWN, quota retained | T13, T14, T16 |
| Altered MCP tool name/description/schema | Pinned allowlist, hash mismatch, deny | T19 |
| Arbitrary browser click or shell | Tool does not exist; unknown calls denied | T19 |

## Known residual risks

- Hosted agents that keep an unmediated browser, terminal or other tool are outside the Contain guarantee.
- Audit hash chaining detects agent-side tampering only; it does not protect against a privileged attacker on the guardian host.
- The v0.1 approval page uses local authentication only. Real high-impact actions would need phishing-resistant step-up auth.
- `SUCCEEDED` means the fake-bank adapter acknowledged a synthetic transfer, not settlement.

## Implementation decisions that refine the design doc

- `RECONCILED` (§8.1) is represented as the `transfer.reconciled` audit event plus the resolved `SUCCEEDED`/`FAILED` state, so a row's state alone decides budget consumption.
- `APPROVED` is budget-consuming (§8.1 omits it). An approved-but-not-dispatched reservation keeps holding headroom.
- Extra deny codes: `IDEMPOTENCY_CONFLICT` (§8.4) and `RATE_LIMITED` (status polling and proposal flooding, §6.4 and §10.2).
