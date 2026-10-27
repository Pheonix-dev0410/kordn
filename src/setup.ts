import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { BankConfig, openBank } from './bank-config.js';
import { AmountMinor, PayeeId, Policy } from './schema.js';

// `kordn setup`: asks which account to guard, the API keys, who the agent may pay and the
// limits, checks the keys, and saves it all in the config dir. A plain `kordn` then uses it.
//
//   policy.json  the rules, also applied to the stored policy right away
//   bank.json    the provider and its id for each payee (not for the mock bank)
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

type Provider = 'mock' | 'paypal' | 'stripe';

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
};

const HELP: Record<Exclude<Provider, 'mock'>, string> = {
  paypal: `You need a PayPal sandbox app (free with any PayPal login):
  1. On developer.paypal.com, under Sandbox accounts, create a US business account.
  2. Under Apps & Credentials (Sandbox), create an app tied to it, and turn on Transaction search.
  3. Copy the app's Client ID and Secret.`,
  stripe: `You need a Stripe test key and a connected account (acct_...) for each payee.
  Dashboard: Developers > API keys (test mode), and Connect > Accounts.`,
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
    let provider: Provider | undefined;
    while (!provider) {
      provider = ({ '': 'mock', '1': 'mock', '2': 'paypal', '3': 'stripe' } as const)[await p.ask('Choose 1, 2 or 3 [1]: ')];
    }
    const info = PROVIDERS[provider];

    const keys: Record<string, string> = {};
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

    let payees: Record<string, string> = {};
    if (provider === 'mock') {
      say('\nThe mock bank knows two payees: utilities and landlord. The AI may pay both.');
      payees = { utilities: '', landlord: '' };
    } else {
      say(`\nWho may the AI pay? For each one, a short name the AI will use (like landlord) and ${info.payeeLabel}.`);
      say('Leave the name empty when you are done.');
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

    say('\nLimits. Amounts in dollars.');
    const dollars = async (question: string, fallback: number) => {
      for (;;) {
        const answer = (await p.ask(`  ${question} [${fallback}]: `)).replace(/^\$/, '');
        if (!answer) return fallback * 100;
        const cents = /^\d+(\.\d{1,2})?$/.test(answer) ? Math.round(Number(answer) * 100) : NaN;
        if (AmountMinor.safeParse(cents).success) return cents;
        say('  Enter an amount like 100 or 49.99.');
      }
    };
    const count = async (question: string, fallback: number) => {
      for (;;) {
        const answer = await p.ask(`  ${question} [${fallback}]: `);
        if (!answer) return fallback;
        if (/^\d{1,4}$/.test(answer)) return Number(answer);
        say('  Enter a whole number.');
      }
    };
    let single = await dollars('Most for one payment', 100);
    let daily = await dollars('Most per day, all payments together', 250);
    while (single > daily) {
      say('  One payment can\'t be more than the daily total.');
      single = await dollars('Most for one payment', 100);
      daily = await dollars('Most per day, all payments together', 250);
    }
    const calls = await count('Most payments per day', 3);
    const approval = await dollars('Ask me first for payments over', 75);

    const policy = Policy.parse({
      schemaVersion: 1,
      policyId: 'kordn-setup',
      agentId: 'my-agent',
      defaultDecision: 'deny',
      resourceId: info.resourceId,
      reads: { allow: true, maxCalls: 30, windowSec: 3600, maxRowsPerCall: 20, maxLookbackDays: 30 },
      transfers: {
        allow: true,
        maxCalls: calls,
        windowSec: 86_400,
        currency: 'USD',
        maxSingleMinor: single,
        maxCumulativeMinor: daily,
        allowedPayeeIds: Object.keys(payees),
        humanApprovalAboveMinor: approval,
      },
    });
    const bank = provider === 'mock' ? undefined : BankConfig.parse({ provider, payees });

    if (bank && (await p.ask(`\nCheck the keys with ${info.label} now? [Y/n]: `)).toLowerCase() !== 'n') {
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
