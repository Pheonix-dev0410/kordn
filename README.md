# kordn

A firewall for AI agents. kordn is an MCP server that sits between an agent and the actions it can take, and enforces limits you set (which payees, how much money, how many calls) outside the model. A prompt injection can change what the agent tries. It can't change what kordn allows.

v0.1 protects a mock bank with fake money only. Don't connect it to real accounts.

> Status: in development. The schemas and test data are in place. The MCP server, guardian and sandbox are being built ([roadmap](../../issues/19)).

## Setup

Requires Node.js 24+.

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

This serves MCP at `http://127.0.0.1:3333/mcp`. Every request needs the header `Authorization: Bearer <random-secret>`. Use a secret of at least 32 characters, e.g. from `openssl rand -hex 32`.

Clients running in the cloud need a public HTTPS URL, so put it behind a tunnel and configure the client with the token. kordn only answers requests addressed to localhost, so tell it the tunnel's hostname:

```sh
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333 --allowed-host <your-tunnel-hostname>
```

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

Anything not explicitly allowed is denied. To keep your policy somewhere else, start kordn with `--policy /path/to/policy.json`.

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
```

Make a branch for each issue, open a pull request into `main`, and link the issue.

## License

Apache-2.0
