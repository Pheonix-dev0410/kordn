# kordn

A firewall for AI agents. kordn is an MCP server that sits between an agent and the actions it can take, and enforces limits you set (which payees, how much money, how many calls) outside the model. A prompt injection can change what the agent tries. It can't change what kordn allows.

> **v0.1.0-alpha is experimental.** kordn runs on your own machine and you use it at your own risk. There is no hosted service and no warranty (see [LICENSE](LICENSE)). Don't rely on it for real money.

## Setup

Requires Node.js 24+. Use the latest patch release.

```sh
git clone https://github.com/Pheonix-dev0410/kordn.git
cd kordn
npm install
npm run build
```

## See it work

```sh
npm run demo
```

A scripted agent does the worst it can against a throwaway copy of the mock bank: obeys a memo telling it to pay an attacker, splits the payment into ten $50s at once, tries to leave the sandbox (Linux with Docker only), keeps going after you press Stop, and retries a transfer whose bank response was lost across a restart. The demo prints what kordn allowed and what the bank actually sent.

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

Anything not explicitly allowed is denied.

kordn keeps its ledger, audit log and the mock bank in `~/.local/state/kordn` (`--data <dir>` to change it), so limits hold across restarts. `examples/policy.json` is only read on the first run; after that the stored policy is used, including edits from the admin UI. To replace it, start kordn with `--policy /path/to/policy.json`. Stopping the agent in the admin UI is permanent for that agent id: to start over, delete the data directory.

## Use your own payment account (test mode)

By default kordn guards a mock bank. It can also guard your own **RazorpayX** account (India, INR payouts) or **Stripe** account (USD transfers to connected accounts). The agent still gets only the four tools above; your API key stays with kordn.

1. In your provider's **test mode**, get API keys and an id for each payee:
   - RazorpayX: a `rzp_test_` key id and secret, your account number, and a fund account (`fa_…`) per payee.
   - Stripe: a `sk_test_` key (a restricted key that can create transfers and read your balance is enough) and a connected account (`acct_…`) per payee.
2. Copy `examples/bank-razorpayx.json` or `examples/bank-stripe.json` and fill in the ids. Every payee in your policy needs one.
3. In your policy, set `resourceId` to `razorpayx:main` and `currency` to `INR` (amounts in paise), or `stripe:main` and `USD` (amounts in cents).
4. Start kordn with the keys in the environment, never in a file:

```sh
claude mcp add kordn \
  -e RAZORPAY_KEY_ID=rzp_test_... -e RAZORPAY_KEY_SECRET=... \
  -- node /absolute/path/to/kordn/dist/index.js --policy /path/to/my-policy.json --bank /path/to/my-bank.json --data ~/.local/state/kordn-razorpayx
```

For Stripe, set `STRIPE_API_KEY` instead. kordn refuses live keys unless you add `--live`; with it, real money moves, at your own risk.

RazorpayX often answers that a payout is still processing. kordn reports it as `unknown` and keeps it counted against your limits until RazorpayX says processed or failed. It checks every 30 seconds and whenever the agent asks for the transfer's status.

## Approve transfers: the admin UI

Add `--admin` to get a local web page where you approve or reject pending transfers, see what the agent did, edit the policy, and stop the agent:

```sh
claude mcp add kordn -- node /absolute/path/to/kordn/dist/index.js --admin
```

kordn prints the page's URL and a login token to stderr. AI clients usually hide that, so both are also in a file only you can read, deleted when kordn exits (also on Ctrl-C, `SIGTERM` or `SIGHUP`):

```sh
cat $XDG_RUNTIME_DIR/kordn/admin-*.json   # without XDG_RUNTIME_DIR: $TMPDIR (usually /tmp)/kordn-<uid>/
```

It listens on `127.0.0.1` only, on a free port (`--admin-port <n>` picks one). It works with `--http` and `kordn contain`, not with `--guardian`: the admin UI runs where the guardian runs.

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

To run the demo agent (a scripted MCP client, v0.1 has no live model) in the sandbox, build the image and start it with Docker running:

```sh
docker build -f sandbox/Dockerfile -t kordn-sandbox .
node dist/index.js contain --admin
```

Before the agent starts, kordn runs 14 isolation checks and prints which passed. Only if all of them pass is it Contain. Otherwise the agent still runs, labelled Guard; `--require-contain` refuses instead. On a normal (rootful) Docker install the result is Guard, and that's correct. [docs/contain.md](docs/contain.md) explains the checks, what real Contain needs, and how to run another agent.

## Project layout

```
src/         source
test/        tests
examples/    example policy
sandbox/     the Contain image and the demo agent
docs/        threat model, Contain mode and the full design doc
```

## Development

```sh
npm run typecheck
npm test                                  # includes the design doc's T01-T20 (test/matrix.test.ts) and the attack tests
KORDN_DOCKER_TESTS=1 npm test             # also the sandbox tests, on Linux with Docker
npm run test:concurrency                  # 50 rounds of concurrency and process-crash tests
```

Make a branch for each issue, open a pull request into `main`, and link the issue. Report security problems privately through GitHub's security advisories, not in issues.

## License

Apache-2.0
