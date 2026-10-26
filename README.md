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

**Codex, Cursor and clients that take a token**

```sh
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333
```

This serves MCP at `http://127.0.0.1:3333/mcp`. Every request needs the header `Authorization: Bearer <random-secret>`. Use a secret of at least 32 characters, e.g. from `openssl rand -hex 32`.

Clients running in the cloud need a public HTTPS URL, so put it behind a tunnel and configure the client with the token. kordn only answers requests addressed to localhost, so tell it the tunnel's hostname:

```sh
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333 --allowed-host <your-tunnel-hostname>
```

**ChatGPT, claude.ai and Grok (OAuth)**

These apps have no field for a token. They sign in with OAuth, so kordn acts as a small OAuth server for you alone. Nothing is hosted and there is no third-party login. Add `--public-url` with the public address of your tunnel:

```sh
cloudflared tunnel --url http://localhost:3333     # prints https://<tunnel-host>
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333 --public-url https://<tunnel-host> --admin
```

`--public-url` turns OAuth on, needs `--http` and doesn't work with `--guardian`. It also allows the tunnel's host, so `--allowed-host` isn't needed. `KORDN_TOKEN` must be 32+ random characters (`openssl rand -hex 32`): it's the one thing standing between a stranger who finds the URL and your approval page. The connector's address is `https://<tunnel-host>/mcp`.

Give kordn a public hostname that stays the same: a named Cloudflare tunnel, an ngrok static domain or Tailscale Funnel. A quick tunnel like the one above gets a new URL every time it starts, and each connector is tied to the URL it was added with. After a restart on a new URL every connector stops working and has to be added again; kordn forgets the apps registered under the old URL when it starts.

> The per-app steps below are to be confirmed by the owner's live test.

1. ChatGPT: Settings, Connectors, turn on developer mode, create a connector with the URL above, authenticating with OAuth.
2. claude.ai: Settings, Connectors, Add custom connector, paste the URL.
3. Grok: add a custom MCP connector with the URL.
4. The app opens kordn's consent page. Check the redirect host shown beside the app's name (the name is whatever the app says it is) and that it belongs to the app you're adding. Then paste `KORDN_TOKEN` and press Approve.
5. Connectors belong to your account in each app, so the same connector shows up in its phone app.

Start kordn with `--admin` to see your apps: each one is listed under Apps in the admin UI, with when it was approved and last used. Press Revoke there and it stops working at once; it has to be approved again to come back. Apps get the same policy and limits as a `KORDN_TOKEN` client.

kordn holds up to 20 connected apps; past that, approving another fails until you revoke one under Apps. An app that hasn't been used for 30 days gives up its place and is dropped; approve it again to bring it back.

**Try it locally with MCP Inspector**

> To be confirmed by the owner's live test.

```sh
KORDN_TOKEN=<random-secret> node dist/index.js --http --port 3333 --public-url http://localhost:3333 --admin
npx @modelcontextprotocol/inspector
```

In Inspector choose transport Streamable HTTP, enter `http://localhost:3333/mcp`, and connect. Approve on the kordn page with the token, then run `tools/list`.

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

By default kordn guards a mock bank. It can also guard your own **PayPal** account (USD payouts to PayPal emails) or **Stripe** account (USD transfers to connected accounts). The agent still gets only the four tools above; your API key stays with kordn.

How each one is tested:
- PayPal: against the real PayPal sandbox. The developer sandbox is free with any PayPal login.
- Stripe: against [stripe-mock](https://github.com/stripe/stripe-mock), Stripe's mock built from their API spec, in CI. That checks every request kordn sends, not Stripe's behaviour, so try it in your own test mode first. New Stripe accounts are invite-only in India.

1. Get test credentials and an id for each payee:
   - PayPal: on developer.paypal.com (Sandbox), create a **US** business sandbox account, then an app under Apps & Credentials tied to it, for its client id and secret. PayPal refuses payouts from Indian accounts, sandbox included (`PAYOUT_NOT_AVAILABLE`). Each payee is a PayPal email; sandbox personal accounts end in `@personal.example.com`.
   - Stripe: a `sk_test_` key (a restricted key that can create transfers and read your balance is enough) and a connected account (`acct_…`) per payee.
2. Copy `examples/bank-paypal.json` or `examples/bank-stripe.json` and fill in the ids. Every payee in your policy needs one.
3. In your policy, set `resourceId` to `paypal:main` or `stripe:main`. Amounts are in cents.
4. Start kordn with the keys in the environment, never in a file:

```sh
claude mcp add kordn \
  -e PAYPAL_CLIENT_ID=... -e PAYPAL_CLIENT_SECRET=... \
  -- node /absolute/path/to/kordn/dist/index.js --policy /path/to/my-policy.json --bank /path/to/my-bank.json --data ~/.local/state/kordn-paypal
```

For Stripe, set `STRIPE_API_KEY` instead. kordn uses the PayPal sandbox and refuses live Stripe keys unless you add `--live`; with it, real money moves, at your own risk.

PayPal often answers that a payout is still processing. kordn reports it as `unknown` and keeps it counted against your limits until PayPal says it went through or failed. It checks every 30 seconds and whenever the agent asks for the transfer's status.

PayPal notes:
- Balance and transaction history need the app's **Transaction search** feature; without it those two tools fail and payouts still work. PayPal updates both up to 3 hours late, so the agent can see a balance from before its latest payouts. kordn's limits don't depend on it: they use kordn's own ledger.
- PayPal can't look a payout up by kordn's id. After a lost reply or a restart, kordn checks by sending a $0 payout with the same id: PayPal either points to the real one or denies the $0 one (`ZERO_AMOUNT`, nothing moves), which also stops the original from arriving late. These denied $0 batches show up in your payout history.
- A payout to an email with no PayPal account is `UNCLAIMED` until claimed or returned after 30 days. kordn counts it as spent.

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
STRIPE_MOCK_URL=http://localhost:12111 npm test  # also the Stripe checks; run stripe/stripe-mock first
npm run test:concurrency                  # 50 rounds of concurrency and process-crash tests
```

Make a branch for each issue, open a pull request into `main`, and link the issue. Report security problems privately through GitHub's security advisories, not in issues.

## License

Apache-2.0
