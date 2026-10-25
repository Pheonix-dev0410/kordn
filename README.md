# Kordn

**A local-first firewall that makes AI-agent permissions enforceable at the tool and operating-system boundary, independent of what the model believes or is instructed to do.**

> ⚠️ Experimental. v0.1 protects a **mock bank with fake money** only. Do not use it to protect real financial operations, and never put real bank credentials anywhere near it.

The model decides what to *try*. The user decides what is *allowed*. A protected action must fail even when the model ignores every safety instruction.

## How it works

```
 ┌──────────── rootless container, --network none ───────────┐
 │  agent-runner (untrusted) ──MCP──▶ mcp-shim (untrusted)    │
 └───────────────────────────────────────│────────────────────┘
                                         │ Unix socket (only mount)
 ┌──────────────── host, trusted ────────▼────────────────────┐
 │  guardian ── policy (pure) ── db (SQLite WAL ledger+audit) │
 │     │                                                      │
 │     └── trusted executor ──▶ adapter-mock ──▶ mock-bank    │
 │  admin-ui (loopback only): policy, approvals, kill switch  │
 └────────────────────────────────────────────────────────────┘
```

The agent can call exactly four typed MCP tools: `af_get_balance`, `af_list_transactions`, `af_propose_transfer`, `af_get_transfer_status`. Every call is re-validated and re-authorized by the guardian against a deterministic policy and an atomic rolling-window ledger. Anything unrecognized is denied.

## Repository layout

| Path | Trust | What |
|---|---|---|
| `packages/contracts` | shared | Zod schemas, types and module interfaces every other package codes against |
| `packages/policy` | trusted | Pure `evaluate()` implementing §6.3 precedence |
| `packages/db` | trusted | SQLite migrations, reservations ledger, hash-chained audit store |
| `packages/guardian` | trusted | Authorization, reservations, executor, IPC server, admin API |
| `packages/adapter-mock` | trusted | Typed, idempotent mock-bank actions with fault injection |
| `packages/launcher` | trusted | Starts services, launches the sandbox, isolation checks |
| `packages/mcp-shim` | **untrusted** | MCP v2 server exposing the four tools, forwards to guardian |
| `apps/mock-bank` | test target | Synthetic accounts, payees and (malicious) memos |
| `apps/admin-ui` | trusted | Loopback-only policy editor, approvals, activity, emergency stop |
| `apps/agent-runner` | **untrusted** | Scripted attacker / optional model loop |
| `tests/{integration,adversarial,concurrency}` | | Cross-package security gates |

The full design is in [`docs/design/Agent_Firewall_Implementation_Design_v0.1.docx`](docs/design/Agent_Firewall_Implementation_Design_v0.1.docx). Section numbers (§) in code and issues refer to it.

## Quick start (development)

```sh
corepack enable          # uses the pnpm version pinned in package.json
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck
pnpm test:unit
```

Requires Node.js 24 LTS. The sandbox (`pnpm sandbox:verify`, `pnpm demo:run`) requires Linux (Ubuntu 24.04 reference) with rootless Docker. See [docs/supported-runtime.md](docs/supported-runtime.md).

## Security claims

See [docs/threat-model.md](docs/threat-model.md) and [docs/coverage.md](docs/coverage.md). In short: for the supported local setup, guarded mock-bank actions cannot execute outside configured rules, assuming the trusted daemon and OS isolation remain uncompromised. We do **not** claim to stop all prompt injection, secure arbitrary hosted agents, or protect real bank accounts.

## License

Apache-2.0
