# kordn

A firewall for AI agents. kordn is an MCP server that sits between an agent and the actions it can take, and enforces limits you set (which payees, how much money, how many calls) outside the model. A prompt injection can change what the agent tries. It can't change what kordn allows.

v0.1 protects a mock bank with fake money only. Don't connect it to real accounts.

> Status: in development. The backend policy, ledger, audit log, mock adapter, and guardian are implemented. The MCP server, admin UI, and sandbox are still being built ([roadmap](../../issues/19)). See the [backend contract](docs/backend.md) for integration and recovery details.

## Setup

Requires a patched Node.js 24 LTS (24.22.1+) or Node.js 26 (26.12.1+).

These are security baselines, rather than minimum versions for API compatibility.
They include the [October 2026 Node.js security fixes](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases),
including fixes to DNS/TLS validation and cached UUID randomness in startup snapshots.
Keep the runtime current within a supported release line; passing tests on an older
runtime does not establish that its bundled dependencies are patched.
The tested Node 24 baseline bundles SQLite 3.53.4, which also includes SQLite's
[WAL-reset corruption fix](https://sqlite.org/wal.html#the_wal_reset_bug).
That fix matters when multiple connections write or checkpoint the same database;
it is present in SQLite 3.51.3+ and the documented upstream backports.

```sh
git clone https://github.com/Pheonix-dev0410/kordn.git
cd kordn
npm install
npm run build
```

## Connect to an AI client

**Claude Code**

```sh
claude mcp add kordn -- node /absolute/path/to/kordn/dist/index.js
```

**Claude Desktop, Cursor, and other clients that use an `mcpServers` config**

```json
{
  "mcpServers": {
    "kordn": {
      "command": "node",
      "args": ["/absolute/path/to/kordn/dist/index.js"]
    }
  }
}
```

**ChatGPT, Grok, and other clients that need a URL**

```sh
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333
```

This serves MCP at `http://127.0.0.1:3333/mcp`. Clients running in the cloud need a public HTTPS URL, so put it behind a tunnel and configure the client with the token.

## Set your limits

Edit `examples/policy.json`:

```jsonc
"transfers": {
  "maxCalls": 3,                    // per 24h
  "maxSingleMinor": 10000,          // $100.00
  "maxCumulativeMinor": 25000,      // $250.00 per 24h
  "allowedPayeeIds": ["utilities", "landlord"],
  "humanApprovalAboveMinor": 7500   // above $75.00 needs your approval
}
```

Anything not explicitly allowed is denied.

## Tools the agent gets

| Tool | What it does |
|---|---|
| `af_get_balance` | Read the mock account balance |
| `af_list_transactions` | Read up to 20 recent transactions. Memos are marked as untrusted text |
| `af_propose_transfer` | Request a transfer. kordn allows, denies, or asks you to approve |
| `af_get_transfer_status` | Check a transfer's state |

## Guard vs Contain

- **Guard** (default): every call through kordn is checked. An agent that also has other tools (a browser, a shell) can go around it.
- **Contain** (Linux): the agent runs in a sandbox with no network and kordn as its only way out. This is the mode the security claims apply to. See [docs/threat-model.md](docs/threat-model.md).

## Project layout

```
src/         source
test/        tests
examples/    example policy
docs/        threat model and the full design doc
```

## Development

```sh
npm run typecheck
npm test
npm run test:concurrency # 50 rounds of concurrency and process-crash tests
```

Make a branch for each issue, open a pull request into `main`, and link the issue.

## License

Apache-2.0
