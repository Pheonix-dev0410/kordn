# Use your own PayPal or Stripe account

By default kordn guards a built-in mock bank, so you can try everything without an account. It can also guard your own **PayPal** account (USD payouts to PayPal emails) or **Stripe** account (USD transfers to connected accounts), in test mode. The agent still gets the same four tools, and your API keys stay with kordn.

How each one is tested:

- **PayPal:** against the real PayPal sandbox. The developer sandbox is free with any PayPal login.
- **Stripe:** against [stripe-mock](https://github.com/stripe/stripe-mock), Stripe's mock built from their API spec, in CI. That checks every request kordn sends, not Stripe's behaviour, so try it in your own test mode first. New Stripe accounts are invite-only in India.

## 1. Get test credentials and an id for each payee

**PayPal**
1. On [developer.paypal.com](https://developer.paypal.com), under Sandbox accounts, create a **US** business account. PayPal refuses payouts from Indian accounts, sandbox included (`PAYOUT_NOT_AVAILABLE`).
2. Under Apps & Credentials, create an app tied to that account. Copy its client id and secret.
3. Turn on the app's **Transaction search** feature, so the agent can read the balance and history.
4. Each payee is a PayPal email. Sandbox personal accounts end in `@personal.example.com`.

**Stripe**
1. A `sk_test_` key. A restricted key that can create transfers and read your balance is enough.
2. A connected account (`acct_…`) for each payee.

## 2. Map your payees

Copy `examples/bank-paypal.json` or `examples/bank-stripe.json` and fill in the ids. Every payee in your policy needs one:

```json
{
  "provider": "paypal",
  "payees": {
    "utilities": "utilities-company@personal.example.com",
    "landlord": "landlord@personal.example.com"
  }
}
```

In your policy, set `resourceId` to `paypal:main` or `stripe:main`. Amounts are in cents.

## 3. Start kordn with the keys in the environment

Keys go in the environment, never in a file in the repo:

```sh
claude mcp add kordn \
  -e PAYPAL_CLIENT_ID=... -e PAYPAL_CLIENT_SECRET=... \
  -- kordn --policy /path/to/my-policy.json --bank /path/to/my-bank.json --data ~/.local/state/kordn-paypal
```

For Stripe, set `STRIPE_API_KEY` instead. A separate `--data` directory keeps this account's ledger apart from the mock bank's.

kordn uses the PayPal sandbox and refuses live Stripe keys unless you add `--live`. With `--live`, real money moves, at your own risk.

## PayPal notes

- PayPal often answers that a payout is still processing. kordn reports it as `unknown` and keeps it counted against your limits until PayPal says it went through or failed. It checks every 30 seconds and whenever the agent asks for the transfer's status.
- Balance and history can be up to 3 hours behind on PayPal's side, so the agent may see a balance from before its latest payouts. kordn's limits don't depend on it: they use kordn's own ledger.
- PayPal can't look a payout up by kordn's id. After a lost reply or a restart, kordn checks by sending a $0 payout with the same id. PayPal either points to the real one or denies the $0 one (`ZERO_AMOUNT`, nothing moves), which also stops the original from arriving late. These denied $0 batches show up in your payout history.
- A payout to an email with no PayPal account stays `UNCLAIMED` until it's claimed, or returned after 30 days. kordn counts it as spent.
