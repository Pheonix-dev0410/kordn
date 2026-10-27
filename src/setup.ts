import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { BankConfig, openBank } from './bank-config.js';
import { hostedLink, sandboxItem, usdAccounts, waitForItem } from './plaid.js';
import type { PlaidEnvironment, PlaidKeys } from './plaid.js';
import { AmountMinor, PayeeId, Policy } from './schema.js';

// `kordn setup`: asks which account to guard, the API keys, who the agent may pay and the
// limits, checks the keys, and saves it all in the config dir. A plain `kordn` then uses it.
//
//   policy.json  the rules, also applied to the stored policy right away
//   bank.json    the provider and its id for each payee, or for Plaid the bank account (not for the mock bank)
//   keys.env     the provider's API keys, KEY=value; the environment wins over it

export function configDir(env: NodeJS.ProcessEnv = process.env): string {
  return join(env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'kordn');
}

export interface SavedSetup {
  policyPath: string;
  bankPath?: string;
  /** The environment plus the saved keys, for openBank. */
  env: NodeJS.ProcessEnv;
}

/** What `kordn setup` saved, or null if it hasn't run. */
export function savedSetup(env: NodeJS.ProcessEnv = process.env): SavedSetup | null {
  const dir = configDir(env);
  const policyPath = join(dir, 'policy.json');
  if (!existsSync(policyPath)) return null;
  const bankPath = join(dir, 'bank.json');
  const keysPath = join(dir, 'keys.env');
  const keys = existsSync(keysPath) ? parseKeys(readFileSync(keysPath, 'utf8')) : {};
  return { policyPath, bankPath: existsSync(bankPath) ? bankPath : undefined, env: { ...keys, ...env } };
}

function parseKeys(text: string): Record<string, string> {
  const keys: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const match = /^\s*([A-Z_][A-Z0-9_]*)=(.*)$/.exec(line);
    if (match) keys[match[1]!] = match[2]!.trim();
  }
  return keys;
}

type Provider = 'mock' | 'paypal' | 'stripe' | 'plaid';

const PROVIDERS: Record<Provider, { label: string; resourceId: string; keys: [string, string, boolean][]; payeeLabel: string; payeeId: RegExp }> = {
  mock: { label: 'the built-in mock bank (pretend money)', resourceId: 'mock-bank:checking-01', keys: [], payeeLabel: '', payeeId: /^$/ },
  paypal: {
    label: 'PayPal (sandbox)',
    resourceId: 'paypal:main',
    keys: [['PAYPAL_CLIENT_ID', 'Client ID', false], ['PAYPAL_CLIENT_SECRET', 'Secret', true]],
    payeeLabel: 'their PayPal email',
    payeeId: /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/,
  },
  stripe: {
    label: 'Stripe (test mode)',
    resourceId: 'stripe:main',
    keys: [['STRIPE_API_KEY', 'Secret key (sk_test_...)', true]],
    payeeLabel: 'their connected account id (acct_...)',
    payeeId: /^acct_[A-Za-z0-9]+$/,
  },
  plaid: {
    label: 'your bank through Plaid (read-only)',
    resourceId: 'plaid:main',
    keys: [['PLAID_CLIENT_ID', 'client_id', false], ['PLAID_SECRET', 'Secret', true]],
    payeeLabel: '',
    payeeId: /^$/,
  },
};

const HELP: Record<Exclude<Provider, 'mock'>, string> = {
  paypal: `You need a PayPal sandbox app (free with any PayPal login):
  1. On developer.paypal.com, under Sandbox accounts, create a US business account.
  2. Under Apps & Credentials (Sandbox), create an app tied to it, and turn on Transaction search.
  3. Copy the app's Client ID and Secret.`,
  stripe: `You need a Stripe test key and a connected account (acct_...) for each payee.
  Dashboard: Developers > API keys (test mode), and Connect > Accounts.`,
  plaid: `You need a Plaid account (free to sign up at dashboard.plaid.com).
  Under Developers > Keys, copy the client_id and the secret for the environment you chose.
  Plaid only reads: the AI can see the balance and transactions, but can't pay anyone.`,
};

/** Reads answers line by line, so it works on a terminal and with piped input alike. */
class Prompter {
  private readonly out = new (class extends Writable {
    muted = false;
    override _write(chunk: Buffer, _encoding: string, done: () => void) {
      if (!this.muted) process.stdout.write(chunk);
      done();
    }
  })();
  private readonly rl = createInterface({ input: process.stdin, output: this.out, terminal: Boolean(process.stdin.isTTY) });
  private readonly lines = this.rl[Symbol.asyncIterator]();

  async ask(question: string, hidden = false): Promise<string> {
    this.rl.setPrompt(question);
    this.rl.prompt();
    this.out.muted = hidden;
    const next = await this.lines.next();
    this.out.muted = false;
    if (hidden || !process.stdin.isTTY) process.stdout.write('\n');
    if (next.done) throw new Error('setup cancelled');
    return next.value.trim();
  }

  close() {
    this.rl.close();
  }
}

export async function runSetup(options: { data?: string }, env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const say = (text = '') => process.stdout.write(`${text}\n`);
  const p = new Prompter();
  try {
    say('kordn setup: answer a few questions, press Enter to take the [default].\n');
    say('Which account should kordn guard?');
    say('  1) the built-in mock bank: pretend money, to try kordn out');
    say('  2) PayPal (sandbox)');
    say('  3) Stripe (test mode)');
    say('  4) a bank account through Plaid: read-only, balance and transactions (US banks)');
    let provider: Provider | undefined;
    while (!provider) {
      provider = ({ '': 'mock', '1': 'mock', '2': 'paypal', '3': 'stripe', '4': 'plaid' } as const)[await p.ask('Choose 1, 2, 3 or 4 [1]: ')];
    }
    const info = PROVIDERS[provider];

    const keys: Record<string, string> = {};
    let environment: PlaidEnvironment = 'sandbox';
    if (provider === 'plaid') {
      say('\nWhich Plaid environment?');
      say('  1) Sandbox: test banks and pretend data');
      say('  2) Production: your real bank. kordn is an alpha: at your own risk');
      let choice: PlaidEnvironment | undefined;
      while (!choice) choice = ({ '': 'sandbox', '1': 'sandbox', '2': 'production' } as const)[await p.ask('Choose 1 or 2 [1]: ')];
      environment = choice;
    }
    if (provider !== 'mock') {
      say(`\n${HELP[provider]}\n`);
      for (const [name, label, hidden] of info.keys) {
        while (!keys[name]) {
          const value = await p.ask(`${label}${hidden ? ' (hidden as you type)' : ''}: `, hidden);
          // Live keys move real money; setup only takes test keys (kordn --live is the deliberate way).
          if (name === 'STRIPE_API_KEY' && value && !/^(sk|rk)_test_/.test(value)) say('  Use a test key: it starts with sk_test_ or rk_test_.');
          else keys[name] = value;
        }
      }
    }

    let plaid: { accountId: string; accessToken: string } | undefined;
    let payees: Record<string, string> = {};
    if (provider === 'plaid') {
      try {
        plaid = await connectPlaid(p, say, { clientId: keys.PLAID_CLIENT_ID!, secret: keys.PLAID_SECRET!, environment });
      } catch (error) {
        throw new Error(`couldn't connect through Plaid (${error instanceof Error ? error.message : String(error)}); nothing saved`);
      }
      keys.PLAID_ACCESS_TOKEN = plaid.accessToken;
    } else if (provider === 'mock') {
      say('\nThe mock bank knows two payees: utilities and landlord. The AI may pay both.');
      payees = { utilities: '', landlord: '' };
    } else {
      say('\nWho may the AI pay? Nobody else can be paid, whatever the AI is told.');
      say(`Add each person: a nickname the AI will use, like landlord, and ${info.payeeLabel}, where the money goes.`);
      say('Press Enter on an empty name when you are done.');
      for (;;) {
        const name = (await p.ask('  Name: ')).toLowerCase();
        if (!name) {
          if (Object.keys(payees).length) break;
          say('  Add at least one.');
          continue;
        }
        if (!PayeeId.safeParse(name).success) {
          say('  Use lowercase letters, digits and dashes, like city-power.');
          continue;
        }
        let id = '';
        while (!info.payeeId.test(id)) {
          if (id) say(`  That doesn't look like ${info.payeeLabel}.`);
          id = await p.ask(`  ${name}: ${info.payeeLabel}: `);
        }
        payees[name] = id;
      }
    }

    // Plaid can't pay, so its payment limits are only placeholders: transfers stay off.
    const readOnly = provider === 'plaid';
    const limits = readOnly ? { daily: 25_000, single: 10_000, calls: 0, approval: 0 } : await askLimits(p, say);
    const { daily, single, calls, approval } = limits;

    const policy = Policy.parse({
      schemaVersion: 1,
      policyId: 'kordn-setup',
      agentId: 'my-agent',
      defaultDecision: 'deny',
      resourceId: info.resourceId,
      reads: { allow: true, maxCalls: 30, windowSec: 3600, maxRowsPerCall: 20, maxLookbackDays: 30 },
      transfers: {
        allow: !readOnly,
        maxCalls: calls,
        windowSec: 86_400,
        currency: 'USD',
        maxSingleMinor: single,
        maxCumulativeMinor: daily,
        allowedPayeeIds: Object.keys(payees),
        humanApprovalAboveMinor: approval,
      },
    });
    const bank = provider === 'mock' ? undefined : BankConfig.parse(plaid ? { provider, accountId: plaid.accountId } : { provider, payees });

    if (bank && !plaid && (await p.ask(`\nCheck the keys with ${info.label} now? [Y/n]: `)).toLowerCase() !== 'n') {
      try {
        const balance = await openBank(bank, policy, { ...env, ...keys }).getBalance(policy.resourceId);
        say(`  Works. Balance: $${(balance.balanceMinor / 100).toFixed(2)}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        say(`  Couldn't read the balance: ${message}`);
        if (provider === 'paypal') say('  If payouts are all you need, that can be fine: balance and history need Transaction search on the app.');
        if ((await p.ask('  Save anyway? [y/N]: ')).toLowerCase() !== 'y') throw new Error('nothing saved; run kordn setup again');
      }
    }

    const dir = configDir(env);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(dir, 0o700);
    const write = (name: string, text: string) => writeFileSync(join(dir, name), text, { mode: 0o600 });
    write('policy.json', `${JSON.stringify(policy, null, 2)}\n`);
    if (bank) {
      write('bank.json', `${JSON.stringify(bank, null, 2)}\n`);
      write('keys.env', Object.entries(keys).map(([k, v]) => `${k}=${v}\n`).join(''));
    } else {
      for (const name of ['bank.json', 'keys.env']) rmSync(join(dir, name), { force: true });
    }

    // Applied now, so the next start enforces it even over edits made in the admin UI before.
    const { defaultDataDir, openLocalGuardian } = await import('./local-guardian.js');
    const local = await openLocalGuardian(options.data ?? defaultDataDir(env), policy, true, bank && ((enforced) => openBank(bank, enforced, { ...env, ...keys })));
    local.close();

    say(`\nSaved in ${dir}. kordn now guards ${info.label}.`);
    say('\nConnect your AI app:');
    say('  Claude Code:                 claude mcp add kordn -- kordn --admin');
    say('  Claude Desktop, Cursor:      add {"command": "kordn", "args": ["--admin"]} under mcpServers');
    say('  ChatGPT, claude.ai, Grok:    kordn --http --tunnel --admin   (see the README)');
  } finally {
    p.close();
  }
}

/** Connects a bank through Plaid: a sandbox test bank, or Plaid's sign-in page in the browser. */
async function connectPlaid(p: Prompter, say: (text?: string) => void, keys: PlaidKeys): Promise<{ accountId: string; accessToken: string }> {
  let accessToken: string;
  let useTestBank = false;
  if (keys.environment === 'sandbox') {
    say('\nConnect a bank:');
    say('  1) a test bank with sample transactions, one of them a planted prompt injection');
    say("  2) sign in on Plaid's page in your browser (sandbox login: user_good / pass_good)");
    useTestBank = (await p.ask('Choose 1 or 2 [1]: ')) !== '2';
  }
  if (useTestBank) {
    accessToken = await sandboxItem(keys);
  } else {
    const link = await hostedLink(keys);
    say(`\nOpen this link, choose your bank and sign in. kordn never sees your bank login:\n  ${link.url}`);
    say('Waiting for you to finish (up to 30 minutes; Ctrl+C to stop)...');
    accessToken = await waitForItem(keys, link.linkToken, {
      onSessionEnded: () => say("  Plaid says the page closed before a bank was connected. If you didn't mean to, open the link again."),
    });
  }

  const accounts = await usdAccounts(keys, accessToken);
  if (!accounts.length) throw new Error('that bank has no checking or savings account in USD');
  let account = accounts[0]!;
  if (accounts.length > 1) {
    say('\nWhich account should kordn guard?');
    accounts.forEach((a, i) => say(`  ${i + 1}) ${a.label}`));
    for (;;) {
      const answer = await p.ask(`Choose 1-${accounts.length} [1]: `);
      const picked = accounts[(answer ? Number(answer) : 1) - 1];
      if (picked) {
        account = picked;
        break;
      }
    }
  }
  const balance = account.balanceMinor === null ? '' : `. Balance: $${(account.balanceMinor / 100).toFixed(2)}`;
  say(`  Connected ${account.label}${balance}`);
  return { accountId: account.id, accessToken };
}

const usd = (minor: number) => `$${(minor / 100).toFixed(minor % 100 ? 2 : 0)}`;

/** The suggested limits in one yes/no, or each one asked in plain words, the daily total first. */
async function askLimits(p: Prompter, say: (text?: string) => void) {
  const describe = (l: { daily: number; single: number; calls: number; approval: number }) => [
    `  - at most ${usd(l.daily)} a day in total`,
    `  - at most ${usd(l.single)} for any one payment`,
    `  - at most ${l.calls} payment${l.calls === 1 ? '' : 's'} a day`,
    `  - payments over ${usd(l.approval)} wait until you approve them on the dashboard`,
  ];
  const suggested = { daily: 25_000, single: 10_000, calls: 3, approval: 7_500 };
  say('\nHow much may the AI spend? Suggested:');
  for (const line of describe(suggested)) say(line);
  const later = 'You can change them any time on the dashboard, under Limits.';
  if ((await p.ask('Use these? [Y/n]: ')).toLowerCase() !== 'n') {
    say(later);
    return suggested;
  }

  const dollars = async (question: string, fallback: number, max = Infinity) => {
    for (;;) {
      const answer = (await p.ask(`  ${question} [${usd(fallback)}]: `)).replace(/^\$/, '');
      const cents = !answer ? fallback : /^\d+(\.\d{1,2})?$/.test(answer) ? Math.round(Number(answer) * 100) : NaN;
      if (!AmountMinor.safeParse(cents).success) say('  Enter an amount like 100 or 49.99.');
      else if (cents > max) say(`  That's more than your daily total of ${usd(max)}. Enter ${usd(max)} or less.`);
      else return cents;
    }
  };
  const count = async (question: string, fallback: number) => {
    for (;;) {
      const answer = await p.ask(`  ${question} [${fallback}]: `);
      if (!answer) return fallback;
      if (/^\d{1,4}$/.test(answer)) return Number(answer);
      say('  Enter a whole number, like 3.');
    }
  };
  say('\nPress Enter to keep a suggestion.');
  const daily = await dollars('How much may the AI spend in a day, in total?', suggested.daily);
  const single = await dollars('The most for any one payment?', Math.min(suggested.single, daily), daily);
  const calls = await count('How many payments a day, at most?', suggested.calls);
  const approval = await dollars('Ask you first for payments over how much?', Math.min(suggested.approval, single));
  const chosen = { daily, single, calls, approval };
  say('\nYour limits:');
  for (const line of describe(chosen)) say(line);
  say(later);
  return chosen;
}
