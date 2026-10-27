import { createHash } from 'node:crypto';
import type { Overview, PendingApproval, TransferSummary } from '../guardian-api.js';
import type { ConnectedApp } from '../oauth/store.js';
import { AmountMinor, AuditEvent, type Policy, type State, type TransferReasonCode } from '../schema.js';
import { POLICY_FIELDS, type PolicyFormValues } from './forms.js';
import { Html, html } from './html.js';

/**
 * guard and contain as decided by the caller. kordn contain shows checking while the isolation
 * checks run, and refused when --require-contain stops the agent from starting.
 */
export const MODES = ['checking', 'guard', 'contain', 'refused'] as const;
export type Mode = (typeof MODES)[number];

// No scripts at all. The one stylesheet is inline and allowed by hash, so the CSP needs
// no 'unsafe-inline' and no route outside the session check.
const CSS = `
:root { color-scheme: light dark; --bg: #f6f7f9; --card: #fff; --text: #16181d; --muted: #5d6470; --line: #e3e6eb;
  --accent: #2f5bea; --accent-text: #fff; --ok: #137a3e; --ok-bg: #e5f5ec; --warn: #8a5a00; --warn-bg: #fff3d6;
  --bad: #b42318; --bad-bg: #fde8e6; --info: #1f4fd1; --info-bg: #e6edff; --dim-bg: #eef0f3; }
@media (prefers-color-scheme: dark) { :root { --bg: #111317; --card: #1a1d23; --text: #e9ebef; --muted: #9aa1ad; --line: #2c3038;
  --accent: #6d8dff; --accent-text: #0b0d12; --ok: #5fd08f; --ok-bg: #16301f; --warn: #f0c060; --warn-bg: #33290f;
  --bad: #ff8a80; --bad-bg: #3a1714; --info: #93acff; --info-bg: #18234a; --dim-bg: #23262d; } }
* { box-sizing: border-box; }
body { margin: 0; font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; color: var(--text); background: var(--bg); }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code { font: 13px ui-monospace, SFMono-Regular, Menlo, monospace; overflow-wrap: anywhere; }
.app { display: flex; min-height: 100vh; }
.side { width: 220px; flex: none; background: var(--card); border-right: 1px solid var(--line); padding: 20px 14px; display: flex; flex-direction: column; gap: 4px; }
.brand { font-size: 20px; font-weight: 700; padding: 0 10px 14px; letter-spacing: -.02em; }
.brand small { display: block; font-size: 12px; font-weight: 400; color: var(--muted); letter-spacing: 0; }
.side nav { display: flex; flex-direction: column; gap: 2px; }
.side nav a { display: flex; justify-content: space-between; align-items: center; padding: 8px 10px; border-radius: 8px; color: var(--text); }
.side nav a:hover { background: var(--dim-bg); text-decoration: none; }
.side nav a.active { background: var(--info-bg); color: var(--info); font-weight: 600; }
.side nav a.danger { color: var(--bad); }
.count { background: var(--warn-bg); color: var(--warn); border-radius: 999px; padding: 0 8px; font-size: 12px; font-weight: 700; }
.side .bottom { margin-top: auto; padding: 10px; font-size: 12px; color: var(--muted); }
.side .bottom button { margin-top: 8px; }
main { flex: 1; min-width: 0; padding: 28px 32px; max-width: 1060px; }
h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -.01em; }
h2 { font-size: 16px; margin: 0 0 12px; }
.lead { color: var(--muted); margin: 0 0 20px; }
.card { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 18px 20px; margin-bottom: 16px; overflow-x: auto; }
.card-head { display: flex; justify-content: space-between; align-items: baseline; gap: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 16px; margin-bottom: 16px; }
.grid .card { margin: 0; }
.label { font-size: 13px; color: var(--muted); }
.big { font-size: 28px; font-weight: 700; letter-spacing: -.02em; margin: 2px 0; }
.note { font-size: 13px; color: var(--muted); margin: 6px 0 0; }
.banner { border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; }
.banner.ok { background: var(--ok-bg); color: var(--ok); }
.banner.bad { background: var(--bad-bg); color: var(--bad); font-weight: 600; }
.banner.warn { background: var(--warn-bg); color: var(--warn); }
.error { background: var(--bad-bg); color: var(--bad); border-radius: 10px; padding: 12px 16px; margin-bottom: 16px; }
.error ul { margin: 0; padding-left: 18px; }
.mode { font-size: 12px; color: var(--muted); border-top: 1px solid var(--line); margin-top: 28px; padding-top: 12px; }
.pill { display: inline-block; border-radius: 999px; padding: 1px 10px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.pill.ok { background: var(--ok-bg); color: var(--ok); }
.pill.warn { background: var(--warn-bg); color: var(--warn); }
.pill.bad { background: var(--bad-bg); color: var(--bad); }
.pill.info { background: var(--info-bg); color: var(--info); }
.pill.dim { background: var(--dim-bg); color: var(--muted); }
table { border-collapse: collapse; width: 100%; }
th { text-align: left; font-size: 12px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; padding: 0 10px 8px; }
td { padding: 10px; border-top: 1px solid var(--line); vertical-align: top; }
td.num, th.num, td.nowrap { text-align: right; white-space: nowrap; }
td.nowrap { text-align: left; }
.when { white-space: nowrap; color: var(--muted); font-size: 13px; }
.empty { color: var(--muted); padding: 8px 0; margin: 0; }
.meter { margin: 12px 0; }
.meter-top { display: flex; justify-content: space-between; font-size: 14px; }
progress { width: 100%; height: 8px; appearance: none; border: 0; border-radius: 999px; background: var(--dim-bg); overflow: hidden; accent-color: var(--accent); }
progress::-webkit-progress-bar { background: var(--dim-bg); border-radius: 999px; }
progress::-webkit-progress-value { background: var(--accent); border-radius: 999px; }
progress::-moz-progress-bar { background: var(--accent); border-radius: 999px; }
button, .button { font: inherit; font-weight: 600; border-radius: 8px; padding: 8px 16px; border: 1px solid var(--line); background: var(--card); color: var(--text); cursor: pointer; }
button:hover { background: var(--dim-bg); }
button.primary { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
button.danger { background: var(--bad); border-color: var(--bad); color: #fff; }
button.small { padding: 4px 12px; font-size: 13px; }
form.inline { display: inline; }
.chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
.chips a { border: 1px solid var(--line); background: var(--card); border-radius: 999px; padding: 3px 12px; font-size: 13px; color: var(--text); }
.chips a.active { background: var(--info-bg); border-color: var(--info-bg); color: var(--info); font-weight: 600; }
.field { margin: 0 0 18px; }
.field label { display: block; font-weight: 600; margin-bottom: 4px; }
.field .hint { font-size: 13px; color: var(--muted); margin: 4px 0 0; }
.input { display: flex; align-items: center; max-width: 260px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); }
.input span { padding: 0 0 0 12px; color: var(--muted); }
.input input { border: 0; background: transparent; }
input, textarea { font: inherit; color: var(--text); padding: 8px 12px; border: 1px solid var(--line); border-radius: 8px; background: var(--bg); width: 100%; }
textarea { max-width: 420px; }
fieldset { border: 0; padding: 0; margin: 0; }
.approval { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px; }
.approval .actions { display: flex; gap: 8px; }
.login { max-width: 420px; margin: 12vh auto; padding: 0 16px; }
.login .brand { padding: 0 0 16px; }
@media (max-width: 760px) {
  .app { flex-direction: column; }
  .side { width: auto; border-right: 0; border-bottom: 1px solid var(--line); padding: 12px; }
  .brand { padding: 0 6px 8px; }
  .side nav { flex-direction: row; flex-wrap: wrap; }
  .side .bottom { display: none; }
  main { padding: 20px 16px; }
  .when { white-space: normal; }
  .card { padding: 14px; }
  td, th { padding-left: 6px; padding-right: 6px; }
}
`;

// Trusted constant, inserted unescaped so the bytes match the CSP hash.
const STYLE = new Html(CSS);

export const CSP = [
  "default-src 'none'",
  `style-src 'sha256-${createHash('sha256').update(CSS).digest('base64')}'`,
  "form-action 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
].join('; ');

const MODE_TEXT: Record<Mode, Html> = {
  // Says nothing about isolation yet: until the checks pass, Guard is all that can be claimed.
  checking: html`<strong>Checking isolation.</strong> The sandbox checks are still running and the agent hasn't
    started. Until they finish, assume Guard mode: only calls that go through kordn are checked.`,
  guard: html`<strong>Guard mode.</strong> mock-bank typed tools protected: every call that goes through kordn is
    checked. Other tools the agent has (a browser, a shell, other apps, hosted agents) are not protected and can
    go around kordn.`,
  contain: html`<strong>Contain mode.</strong> mock-bank typed tools protected: the agent runs in a sandbox with
    no network and kordn is its only way out. Browsers, apps and hosted agents outside the sandbox are not
    protected.`,
  refused: html`<strong>Refused.</strong> The isolation checks failed and kordn was told to require full isolation,
    so the agent was not started.`,
};

type NavKey = 'overview' | 'approvals' | 'payments' | 'activity' | 'policy' | 'apps' | 'stop';

export interface PageContext {
  mode: Mode;
  agentId: string;
  /** Present when logged in: adds navigation and the logout form. */
  csrf?: string;
  /** The agent's revoked state, shown on every logged-in page. */
  revoked?: boolean;
  /** OAuth is on: adds the Apps link. */
  apps?: boolean;
  /** Transfers waiting for approval, counted beside Approvals. */
  pending?: number;
  flash?: string | null;
  errors?: readonly string[];
  /** Milliseconds since the epoch, for "5 min ago". */
  now?: number;
  /** A real account, not a test one: a warning on every page. */
  live?: boolean;
}

// ---- Formatting ----

/** "$4,823.15". Integer arithmetic only. */
export function money(minor: number): string {
  const sign = minor < 0 ? '-' : '';
  const abs = Math.abs(minor);
  const dollars = Math.floor(abs / 100).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  return `${sign}$${dollars}.${String(abs % 100).padStart(2, '0')}`;
}

/** Local time with a relative hint, e.g. "Oct 27, 5:03 PM · 4 min ago". */
function when(iso: string, now = Date.now()): Html {
  const t = Date.parse(iso);
  const local = new Date(t).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
  const ago = relative(now - t);
  return html`<span class="when" title="${iso}">${local}${ago ? html` · ${ago}` : null}</span>`;
}

function relative(ms: number): string {
  const future = ms < 0;
  const s = Math.abs(ms) / 1000;
  const text = s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)} min` : s < 86_400 ? `${Math.floor(s / 3600)} h` : '';
  if (!text || text === 'just now') return text;
  return future ? `in ${text}` : `${text} ago`;
}

const STATE_PILL: Record<State, [string, string]> = {
  RESERVED: ['Sending', 'info'],
  PENDING_APPROVAL: ['Waiting for you', 'warn'],
  APPROVED: ['Sending', 'info'],
  DISPATCHING: ['Sending', 'info'],
  UNKNOWN: ['Waiting for the bank', 'warn'],
  SUCCEEDED: ['Sent', 'ok'],
  FAILED: ['Failed', 'bad'],
  REJECTED: ['Rejected', 'dim'],
  EXPIRED: ['Expired', 'dim'],
};

function pill(text: string, tone: string): Html {
  return html`<span class="pill ${tone}">${text}</span>`;
}

const REASONS: Record<TransferReasonCode, string> = {
  SESSION_REVOKED: 'the AI was stopped',
  ISOLATION_FAILED: 'the sandbox checks failed',
  UNKNOWN_ACTION: 'that is not something kordn allows',
  INVALID_ARGUMENTS: 'the request was malformed',
  CAPABILITY_DISABLED: 'that is turned off in your limits',
  UNAPPROVED_PAYEE: 'not on your payee list',
  SINGLE_LIMIT: 'over your limit for one payment',
  FREQUENCY_LIMIT: 'over your limit for how often',
  CUMULATIVE_LIMIT: 'over your daily total',
  APPROVAL_EXPIRED: "it wasn't approved in time",
  INTERNAL_UNAVAILABLE: "kordn or the bank didn't answer",
  IDEMPOTENCY_CONFLICT: 'it reused a payment id with different details',
  RATE_LIMITED: 'it asked too often',
  ADAPTER_FAILED: 'the bank refused it',
};

export function reason(code: TransferReasonCode | null): string {
  return code ? REASONS[code] : '';
}

const TOOL_WORDS: Record<string, string> = {
  af_get_balance: 'read the balance',
  af_list_transactions: 'read the transactions',
  af_propose_transfer: 'asked to make a payment',
  af_get_transfer_status: 'checked on a payment',
};

// ---- Layout ----

export function layout(ctx: PageContext, title: string, body: Html, current?: NavKey): Html {
  const link = (key: NavKey, href: string, label: string, extra?: Html | null) => {
    const cls = [key === current ? 'active' : '', key === 'stop' ? 'danger' : ''].join(' ').trim();
    return html`<a href="${href}"${cls ? html` class="${cls}"` : null}>${label}${extra ?? null}</a>`;
  };
  const errors = ctx.errors?.length
    ? html`<div class="error" role="alert"><ul>${ctx.errors.map((e) => html`<li>${e}</li>`)}</ul></div>`
    : null;
  const banners = html`${ctx.live ? html`<p class="banner bad" role="note">Live: this is a real account, and payments move real money.</p>` : null}
${ctx.revoked ? html`<p class="banner bad" role="alert">Agent stopped. New calls and approvals are refused.</p>` : null}
${ctx.flash ? html`<p class="banner ok" role="status">${ctx.flash}</p>` : null}
${errors}`;
  const head = html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · kordn admin</title>
<style>${STYLE}</style>
</head>`;
  if (!ctx.csrf) {
    return html`${head}
<body>
<div class="login">
<div class="brand">kordn <small>experimental local prototype · agent <code>${ctx.agentId}</code></small></div>
${banners}
<h1>${title}</h1>
${body}
<p class="mode">${MODE_TEXT[ctx.mode]}</p>
</div>
</body>
</html>
`;
  }
  return html`${head}
<body>
<div class="app">
<aside class="side">
  <div class="brand">kordn <small>agent <code>${ctx.agentId}</code></small></div>
  <nav>
    ${link('overview', '/', 'Overview')}
    ${link('approvals', '/approvals', 'Approvals', ctx.pending ? html`<span class="count">${ctx.pending}</span>` : null)}
    ${link('payments', '/payments', 'Payments')}
    ${link('activity', '/activity', 'Activity')}
    ${link('policy', '/policy', 'Limits')}
    ${ctx.apps ? link('apps', '/apps', 'Apps') : null}
    ${link('stop', '/stop', 'Stop')}
  </nav>
  <div class="bottom">
    experimental local prototype
    <form method="post" action="/logout"><input type="hidden" name="csrf" value="${ctx.csrf}"><button class="small">Log out</button></form>
  </div>
</aside>
<main>
${banners}
<h1>${title}</h1>
${body}
<p class="mode">${MODE_TEXT[ctx.mode]}</p>
</main>
</div>
</body>
</html>
`;
}

export function loginPage(ctx: PageContext): Html {
  return layout(
    ctx,
    'Log in',
    html`<p class="lead">Paste the admin login token kordn printed when it started.</p>
    <form method="post" action="/login" class="card">
      <div class="field">
        <label for="token">Admin token (printed when kordn started)</label>
        <input id="token" name="token" type="password" autocomplete="off" required>
      </div>
      <button class="primary">Log in</button>
    </form>`,
  );
}

// ---- Overview ----

function meter(label: string, used: string, limit: string, value: number, max: number): Html {
  return html`<div class="meter">
    <div class="meter-top"><span>${label}</span><span><strong>${used}</strong> of ${limit}</span></div>
    <progress value="${Math.min(value, max)}" max="${Math.max(max, 1)}">${used} of ${limit}</progress>
  </div>`;
}

function transferRows(transfers: readonly TransferSummary[], now?: number): Html {
  return html`<table>
    <tr><th>When</th><th>Payee</th><th class="num">Amount</th><th>Status</th></tr>
    ${transfers.map((t) => {
      const [text, tone] = STATE_PILL[t.state];
      const why = reason(t.reasonCode);
      return html`<tr>
        <td>${when(t.createdAt, now)}</td>
        <td class="nowrap"><code>${t.payeeId}</code></td>
        <td class="num">${money(t.amountMinor)}</td>
        <td>${pill(text, tone)}${why ? html`<div class="note">${why}</div>` : null}</td>
      </tr>`;
    })}
  </table>`;
}

export function overviewPage(ctx: PageContext & { csrf: string }, overview: Overview, policy: Policy, transfers: readonly TransferSummary[], events: readonly AuditEvent[]): Html {
  const t = policy.transfers;
  const { usage } = overview;
  const running = !ctx.revoked;
  const recent = transfers.slice(0, 5);
  return layout(
    ctx,
    'Overview',
    html`<p class="lead">What your AI can do, and what it has done.</p>
    <div class="grid">
      <div class="card">
        <div class="label">AI agent</div>
        <div class="big">${running ? 'Running' : 'Stopped'}</div>
        ${running ? pill('Rules enforced', 'ok') : pill('All calls refused', 'bad')}
      </div>
      <div class="card">
        <div class="label">Account <code>${policy.resourceId}</code></div>
        <div class="big">${overview.balance ? money(overview.balance.balanceMinor) : '—'}</div>
        <p class="note">${overview.balance ? html`Balance as of ${when(overview.balance.observedAt, ctx.now)}` : 'The bank did not answer just now.'}</p>
      </div>
      <div class="card">
        <div class="label">Waiting for you</div>
        <div class="big">${ctx.pending ?? 0}</div>
        <p class="note">${ctx.pending ? html`<a href="/approvals">Review approvals</a>` : 'Nothing to approve.'}</p>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><h2>Usage against your limits</h2><a href="/policy">Change limits</a></div>
      ${meter(`Payments, last ${hours(t.windowSec)}`, String(usage.transfers), String(t.maxCalls), usage.transfers, t.maxCalls)}
      ${meter(`Money sent or waiting, last ${hours(t.windowSec)}`, money(usage.transferredMinor), money(t.maxCumulativeMinor), usage.transferredMinor, t.maxCumulativeMinor)}
      ${meter(`Reads, last ${hours(policy.reads.windowSec)}`, String(usage.reads), String(policy.reads.maxCalls), usage.reads, policy.reads.maxCalls)}
      <p class="note">One payment at most ${money(t.maxSingleMinor)}. You approve anything over ${money(t.humanApprovalAboveMinor)}.
        Allowed payees: ${t.allowedPayeeIds.length ? t.allowedPayeeIds.map((p, i) => html`${i ? ', ' : ''}<code>${p}</code>`) : 'none'}.</p>
    </div>
    <div class="card">
      <div class="card-head"><h2>Recent payments</h2><a href="/payments">All payments</a></div>
      ${recent.length ? transferRows(recent, ctx.now) : html`<p class="empty">No payments yet.</p>`}
    </div>
    <div class="card">
      <div class="card-head"><h2>Recent activity</h2><a href="/activity">All activity</a></div>
      ${events.length ? activityRows(events, transfers, ctx.now, false) : html`<p class="empty">Nothing yet.</p>`}
    </div>`,
    'overview',
  );
}

function hours(sec: number): string {
  return sec % 86_400 === 0 ? (sec === 86_400 ? '24 hours' : `${sec / 86_400} days`) : sec % 3600 === 0 ? (sec === 3600 ? 'hour' : `${sec / 3600} hours`) : `${sec} s`;
}

export function paymentsPage(ctx: PageContext & { csrf: string }, transfers: readonly TransferSummary[]): Html {
  return layout(
    ctx,
    'Payments',
    html`<p class="lead">Every payment the AI asked for that passed your rules, newest first. Refused requests are under
      <a href="/activity?type=denied">Activity</a>.</p>
    <div class="card">${transfers.length ? transferRows(transfers, ctx.now) : html`<p class="empty">No payments yet.</p>`}</div>`,
    'payments',
  );
}

// ---- Limits ----

export interface PolicyView {
  policyId: string;
  resourceId: string;
  currency: string;
  version: number;
  values: PolicyFormValues;
  /** Bank-backed accounts need an id for every payee, which only kordn setup or --bank adds. */
  realBank?: boolean;
  /** Transfers are off in the policy, as for a read-only Plaid account: no payment fields. */
  paymentsOff?: boolean;
}

const FIELD_HELP: Record<(typeof POLICY_FIELDS)[number]['name'], string> = {
  maxSingleUsd: 'No single payment can be bigger than this.',
  maxTotalUsd: 'All payments in 24 hours together can\'t go over this.',
  transfersPerDay: 'How many payments the AI can make in 24 hours.',
  approvalAboveUsd: 'Payments above this wait until you approve them under Approvals.',
  readsPerHour: 'How often the AI can look at the balance and transactions.',
};

export function policyPage(ctx: PageContext & { csrf: string }, view: PolicyView): Html {
  const field = (name: (typeof POLICY_FIELDS)[number]['name']) => {
    const f = POLICY_FIELDS.find((x) => x.name === name)!;
    const input = html`<input id="${f.name}" name="${f.name}" value="${view.values[f.name]}" inputmode="${f.kind === 'usd' ? 'decimal' : 'numeric'}" required>`;
    return html`<div class="field">
      <label for="${f.name}">${f.label}</label>
      ${f.kind === 'usd' ? html`<div class="input"><span>$</span>${input}</div>` : html`<div class="input">${input}</div>`}
      <p class="hint">${FIELD_HELP[f.name]}</p>
    </div>`;
  };
  return layout(
    ctx,
    'Limits',
    html`<p class="lead">For <code>${view.resourceId}</code>, in ${view.currency}. Changes apply to the AI's next request.
      <span class="note">Policy <code>${view.policyId}</code>, version ${view.version}.</span></p>
    <form method="post" action="/policy">
      <input type="hidden" name="csrf" value="${ctx.csrf}">
      <input type="hidden" name="version" value="${view.version}">
      ${view.paymentsOff
        ? html`<div class="card">
            <h2>Payments</h2>
            <p class="hint">Off for this account: the AI can read it, but can't pay anyone.</p>
            ${(['maxSingleUsd', 'maxTotalUsd', 'transfersPerDay', 'approvalAboveUsd', 'payees'] as const).map(
              (name) => html`<input type="hidden" name="${name}" value="${view.values[name]}">`,
            )}
          </div>`
        : html`<div class="card">
            <h2>Payments</h2>
            ${field('maxSingleUsd')}
            ${field('maxTotalUsd')}
            ${field('transfersPerDay')}
            ${field('approvalAboveUsd')}
          </div>
          <div class="card">
            <h2>Who the AI may pay</h2>
            <div class="field">
              <label for="payees">Allowed payees (one id per line)</label>
              <textarea id="payees" name="payees" rows="5">${view.values.payees}</textarea>
              <p class="hint">Payments to anyone else are refused.${view.realBank
                ? ' A new payee also needs their PayPal email or Stripe account id: add it with kordn setup.'
                : ' The mock bank knows utilities and landlord.'}</p>
            </div>
          </div>`}
      <div class="card">
        <h2>Reading</h2>
        ${field('readsPerHour')}
      </div>
      <p><button class="primary">Save limits</button></p>
    </form>`,
    'policy',
  );
}

// ---- Approvals ----

export function approvalsPage(ctx: PageContext & { csrf: string }, pending: readonly PendingApproval[]): Html {
  const csrf = html`<input type="hidden" name="csrf" value="${ctx.csrf}">`;
  const cards = pending.map((p) => {
    // Never offer to approve an amount we can't show exactly. Reject stays, to clear it.
    const valid = AmountMinor.safeParse(p.amountMinor).success;
    return html`<div class="card approval">
      <div>
        <div class="big">${valid ? money(p.amountMinor) : html`<strong>Invalid amount</strong>`}</div>
        <div>to <code>${p.payeeId}</code> from <code>${p.resourceId}</code> ${valid ? p.currency : null}</div>
        <p class="note">Asked by <code>${p.agentId}</code> · expires ${when(p.expiresAt, ctx.now)} · policy version ${p.policyVersion}</p>
        <p class="note"><code>${p.reservationId}</code></p>
      </div>
      <div class="actions">
        ${
          valid
            ? html`<form class="inline" method="post" action="/approvals/approve">${csrf}
          <input type="hidden" name="reservationId" value="${p.reservationId}">
          <input type="hidden" name="digest" value="${p.digest}">
          <input type="hidden" name="nonce" value="${p.nonce}">
          <button class="primary">Approve</button>
        </form>`
            : null
        }
        <form class="inline" method="post" action="/approvals/reject">${csrf}
          <input type="hidden" name="reservationId" value="${p.reservationId}">
          <input type="hidden" name="nonce" value="${p.nonce}">
          <button>Reject</button>
        </form>
      </div>
    </div>`;
  });
  return layout(
    ctx,
    'Approvals',
    html`<p class="lead">Payments above your approval threshold wait here. Each can be approved or rejected once.
      Approving re-checks every limit; it can't override a hard deny.</p>
    ${pending.length === 0 ? html`<div class="card"><p class="empty">Nothing is waiting for approval.</p></div>` : cards}`,
    'approvals',
  );
}

// ---- Apps ----

export function appsPage(ctx: PageContext & { csrf: string }, apps: readonly ConnectedApp[]): Html {
  const rows = apps.map(
    (a) => html`<tr>
      <td><strong>${a.name}</strong><div class="note"><code>${a.redirectHost}</code></div></td>
      <td>${when(new Date(a.approvedAt).toISOString(), ctx.now)}</td>
      <td>${a.lastUsedAt === null ? 'never' : when(new Date(a.lastUsedAt).toISOString(), ctx.now)}</td>
      <td class="num">
        <form class="inline" method="post" action="/apps/revoke">
          <input type="hidden" name="csrf" value="${ctx.csrf}">
          <input type="hidden" name="client" value="${a.clientId}">
          <button class="small">Revoke</button>
        </form>
      </td>
    </tr>`,
  );
  return layout(
    ctx,
    'Connected apps',
    html`<p class="lead">Apps you approved to use this kordn over OAuth, like ChatGPT or claude.ai. Revoking one ends its
      access at once; it has to be approved again to reconnect.</p>
    <div class="card">${
      apps.length === 0
        ? html`<p class="empty">No apps are connected.</p>`
        : html`<table>
          <tr><th>App</th><th>Approved</th><th>Last used</th><th></th></tr>
          ${rows}
        </table>`
    }</div>`,
    'apps',
  );
}

// ---- Activity ----

export const ACTIVITY_FILTERS = {
  allowed: ['policy.allowed'],
  denied: ['policy.denied'],
  pending: ['policy.require_approval'],
  succeeded: ['transfer.succeeded'],
  unknown: ['transfer.unknown'],
  apps: ['oauth.approved', 'oauth.denied', 'oauth.revoked', 'oauth.refresh_reused'],
  everything: AuditEvent.shape.event.options,
} as const satisfies Record<string, readonly AuditEvent['event'][]>;

export type ActivityType = keyof typeof ACTIVITY_FILTERS;

/** The default view leaves out the bookkeeping: every call's attempt, dispatch and read records. */
export const ACTIVITY_DEFAULT: readonly AuditEvent['event'][] = AuditEvent.shape.event.options.filter(
  (e) => !['action.attempted', 'transfer.dispatching', 'read.executed'].includes(e),
);

const FILTER_LABELS: Record<ActivityType | 'all', string> = {
  all: 'All',
  allowed: 'Allowed',
  denied: 'Refused',
  pending: 'Waiting for you',
  succeeded: 'Sent',
  unknown: 'Waiting for the bank',
  apps: 'Apps',
  everything: 'Everything (technical)',
};

/** One audit event as a sentence, with a tone for its pill. */
export function describe(e: AuditEvent, payments: ReadonlyMap<string, TransferSummary>): { tone: string; tag: string; text: Html } {
  const p = e.reservationId ? payments.get(e.reservationId) : undefined;
  const meta = e.metadata;
  const amount = typeof meta.amountMinor === 'number' ? meta.amountMinor : p?.amountMinor;
  const payee = typeof meta.payeeId === 'string' ? meta.payeeId : p?.payeeId;
  const what = amount !== undefined && payee !== undefined ? html`${money(amount)} to <code>${payee}</code>` : html`a payment`;
  const why = e.reasonCode ? `: ${REASONS[e.reasonCode]}` : '';
  const app = html`<strong>${String(meta.client ?? 'an app')}</strong> (<code>${String(meta.redirectHost ?? '')}</code>)`;
  switch (e.event) {
    case 'policy.allowed':
      if (e.tool === 'af_propose_transfer') return { tone: 'ok', tag: 'Allowed', text: meta.duplicate ? html`Retry of ${what}, not sent again` : html`Payment of ${what}` };
      return { tone: 'dim', tag: 'Read', text: html`The AI ${TOOL_WORDS[e.tool ?? ''] ?? 'made a call'}` };
    case 'policy.denied':
      if (e.tool === 'af_propose_transfer') return { tone: 'bad', tag: 'Refused', text: html`Payment of ${what}${why}` };
      return { tone: 'bad', tag: 'Refused', text: html`The AI ${e.tool ? TOOL_WORDS[e.tool] : 'made a call'}${why}` };
    case 'policy.require_approval':
      return { tone: 'warn', tag: 'Waiting', text: html`${what} needs your approval` };
    case 'approval.granted':
      return { tone: 'ok', tag: 'Approved', text: html`You approved ${what}` };
    case 'approval.rejected':
      return { tone: 'dim', tag: 'Rejected', text: html`${what} was rejected${why}` };
    case 'approval.expired':
      return { tone: 'dim', tag: 'Expired', text: html`${what} expired before anyone approved it` };
    case 'transfer.dispatching':
      return { tone: 'info', tag: 'Sending', text: html`Sending ${what} to the bank` };
    case 'transfer.succeeded':
      return { tone: 'ok', tag: 'Sent', text: html`The bank sent ${what}` };
    case 'transfer.failed':
      return { tone: 'bad', tag: 'Failed', text: html`The bank didn't send ${what}${why}` };
    case 'transfer.unknown':
      return { tone: 'warn', tag: 'Unknown', text: html`No answer yet from the bank about ${what}. It stays counted until there is one` };
    case 'transfer.reconciled':
      return { tone: 'info', tag: 'Settled', text: html`Settled ${what} after a lost reply or restart` };
    case 'read.executed':
      return { tone: 'dim', tag: 'Read', text: html`The AI ${TOOL_WORDS[e.tool ?? ''] ?? 'read the account'}` };
    case 'session.revoked':
      return { tone: 'bad', tag: 'Stopped', text: html`You stopped the AI` };
    case 'policy.updated':
      return { tone: 'info', tag: 'Limits', text: html`Limits changed${e.policyVersion !== null ? ` (version ${e.policyVersion})` : ''}` };
    case 'oauth.approved':
      return { tone: 'ok', tag: 'App', text: html`You connected ${app}` };
    case 'oauth.denied':
      return { tone: 'dim', tag: 'App', text: html`You denied ${app}` };
    case 'oauth.revoked':
      return { tone: 'dim', tag: 'App', text: html`You revoked ${app}` };
    case 'oauth.refresh_reused':
      return { tone: 'bad', tag: 'App', text: html`A stolen or replayed sign-in for ${app} was blocked; it has to sign in again` };
    case 'action.attempted':
      if (meta.reason === 'connection_limit') return { tone: 'bad', tag: 'Refused', text: html`Refused ${String(meta.refused ?? 1)} connection(s) over the limit` };
      return { tone: 'dim', tag: 'Call', text: html`The AI ${e.tool ? TOOL_WORDS[e.tool] : 'called something kordn does not offer'}` };
  }
}

/** `technical` adds a line with the raw event, codes and metadata under each sentence. */
function activityRows(events: readonly AuditEvent[], transfers: readonly TransferSummary[], now?: number, technical = true): Html {
  const payments = new Map(transfers.map((t) => [t.reservationId, t]));
  return html`<table>
    <tr><th>When</th><th></th><th>What happened</th></tr>
    ${events.map((e) => {
      const d = describe(e, payments);
      return html`<tr>
        <td>${when(e.timestamp, now)}</td>
        <td>${pill(d.tag, d.tone)}</td>
        <td>${d.text}${technical ? html`<div class="note">${e.event}${e.reasonCode ? html` · ${e.reasonCode}` : null}${e.reservationId ? html` · <code>${e.reservationId}</code>` : null}${e.policyVersion !== null ? ` · policy v${e.policyVersion}` : ''}${Object.entries(e.metadata).map(([k, v]) => html` · <code>${k}=${String(v)}</code>`)}</div>` : null}</td>
      </tr>`;
    })}
  </table>`;
}

export function activityPage(ctx: PageContext, events: readonly AuditEvent[], type: ActivityType | null, transfers: readonly TransferSummary[] = []): Html {
  const chips = (['all', ...Object.keys(ACTIVITY_FILTERS)] as (ActivityType | 'all')[]).map((t) => {
    const active = (t === 'all' && type === null) || t === type;
    return html`<a href="${t === 'all' ? '/activity' : `/activity?type=${t}`}" class="${active ? 'active' : ''}">${FILTER_LABELS[t]}</a>`;
  });
  return layout(
    ctx,
    'Activity',
    html`<p class="lead">Everything the AI asked for and what kordn decided, newest first.</p>
    <nav class="chips">${chips}</nav>
    <div class="card">${events.length === 0 ? html`<p class="empty">No matching activity.</p>` : activityRows(events, transfers, ctx.now)}</div>`,
    'activity',
  );
}

// ---- Stop ----

export function stopPage(ctx: PageContext & { csrf: string }, revoked: boolean, unknown: readonly AuditEvent[]): Html {
  return layout(
    ctx,
    'Emergency stop',
    html`<div class="card">${
      revoked
        ? html`<p><strong>Agent stopped.</strong> New calls are denied and pending approvals were rejected.</p>
          <p class="note">This is permanent for this agent. To start over, delete kordn's data folder.</p>`
        : html`<p><strong>Agent is running.</strong> Stopping denies its new calls and rejects pending approvals immediately.</p>
          <p class="note">This is permanent for this agent. To start over, you'd delete kordn's data folder.</p>
          <form method="post" action="/stop">
            <input type="hidden" name="csrf" value="${ctx.csrf}">
            <button class="danger">Stop the agent</button>
          </form>`
    }</div>
    <div class="card">
      <h2>Transfers with unknown outcome</h2>
      <p class="note">Stopping does not undo anything: transfers already sent to the bank are not rolled back. A transfer
        whose outcome is unknown keeps its quota held until it is reconciled.
        <a href="/activity?type=unknown">See unknown outcomes in Activity</a>.</p>
      ${
        unknown.length === 0
          ? html`<p class="empty">None recorded.</p>`
          : html`<ul>${unknown.map((e) => html`<li>${when(e.timestamp, ctx.now)} <code>${e.reservationId}</code></li>`)}</ul>`
      }
    </div>`,
    'stop',
  );
}
