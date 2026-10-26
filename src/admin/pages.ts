import { createHash } from 'node:crypto';
import type { PendingApproval } from '../guardian-api.js';
import { AmountMinor, type AuditEvent } from '../schema.js';
import { formatUsd, POLICY_FIELDS, type PolicyFormValues } from './forms.js';
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
body { font: 15px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 0 auto; padding: 1rem; color: #1a1a1a; background: #fff; }
header, .mode { border-bottom: 1px solid #ccc; padding-bottom: .5rem; margin-bottom: 1rem; }
nav a, nav button { margin-right: 1rem; }
nav form { display: inline; }
.mode { background: #fff6d6; padding: .5rem; border: 1px solid #e0c060; }
.stopped { background: #b00020; color: #fff; padding: .5rem; font-weight: 600; }
form.inline { display: inline; }
.flash { background: #e3f6e3; padding: .5rem; }
.error { background: #fde2e2; padding: .5rem; }
label { display: block; margin-top: .75rem; font-weight: 600; }
input, textarea { font: inherit; padding: .25rem; }
table { border-collapse: collapse; width: 100%; }
td, th { border-bottom: 1px solid #ddd; padding: .25rem .5rem; text-align: left; vertical-align: top; }
code { word-break: break-all; }
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

export interface PageContext {
  mode: Mode;
  agentId: string;
  /** Present when logged in: adds navigation and the logout form. */
  csrf?: string;
  /** The agent's revoked state, shown on every logged-in page. */
  revoked?: boolean;
  flash?: string | null;
  errors?: readonly string[];
}

export function layout(ctx: PageContext, title: string, body: Html): Html {
  const nav = ctx.csrf
    ? html`<nav>
        <a href="/approvals">Approvals</a>
        <a href="/activity">Activity</a>
        <a href="/policy">Policy</a>
        <a href="/stop">Stop</a>
        <form method="post" action="/logout"><input type="hidden" name="csrf" value="${ctx.csrf}"><button>Log out</button></form>
      </nav>`
    : null;
  const errors = ctx.errors?.length
    ? html`<div class="error" role="alert"><ul>${ctx.errors.map((e) => html`<li>${e}</li>`)}</ul></div>`
    : null;
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title} · kordn admin</title>
<style>${STYLE}</style>
</head>
<body>
<header><strong>kordn admin</strong> · agent <code>${ctx.agentId}</code> · experimental local prototype ${nav}</header>
<p class="mode">${MODE_TEXT[ctx.mode]}</p>
${ctx.revoked ? html`<p class="stopped" role="alert">Agent stopped. New calls and approvals are refused.</p>` : null}
${ctx.flash ? html`<p class="flash" role="status">${ctx.flash}</p>` : null}
${errors}
<h1>${title}</h1>
${body}
</body>
</html>
`;
}

export function loginPage(ctx: PageContext): Html {
  return layout(
    ctx,
    'Log in',
    html`<form method="post" action="/login">
      <label for="token">Admin token (printed when kordn started)</label>
      <input id="token" name="token" type="password" autocomplete="off" required>
      <button>Log in</button>
    </form>`,
  );
}

export interface PolicyView {
  policyId: string;
  resourceId: string;
  currency: string;
  version: number;
  values: PolicyFormValues;
}

export function policyPage(ctx: PageContext & { csrf: string }, view: PolicyView): Html {
  return layout(
    ctx,
    'Limits',
    html`<p>Policy <code>${view.policyId}</code>, version ${view.version}, for <code>${view.resourceId}</code>.
      Amounts are in ${view.currency}. Tighter limits apply to new requests immediately.</p>
    <form method="post" action="/policy">
      <input type="hidden" name="csrf" value="${ctx.csrf}">
      <input type="hidden" name="version" value="${view.version}">
      ${POLICY_FIELDS.map(
        (f) => html`<label for="${f.name}">${f.label}</label>
          <input id="${f.name}" name="${f.name}" value="${view.values[f.name]}" inputmode="${f.kind === 'usd' ? 'decimal' : 'numeric'}" required>`,
      )}
      <label for="payees">Allowed payees (one id per line)</label>
      <textarea id="payees" name="payees" rows="5" cols="40">${view.values.payees}</textarea>
      <p><button>Save limits</button></p>
    </form>`,
  );
}

export function approvalsPage(ctx: PageContext & { csrf: string }, pending: readonly PendingApproval[]): Html {
  const csrf = html`<input type="hidden" name="csrf" value="${ctx.csrf}">`;
  const rows = pending.map((p) => {
    // Never offer to approve an amount we can't show exactly. Reject stays, to clear it.
    const valid = AmountMinor.safeParse(p.amountMinor).success;
    return html`<tr>
      <td><code>${p.agentId}</code></td>
      <td><code>${p.payeeId}</code></td>
      <td>${valid ? html`${formatUsd(p.amountMinor)} ${p.currency}` : html`<strong>Invalid amount</strong>`}</td>
      <td><code>${p.resourceId}</code></td>
      <td>${p.policyVersion}</td>
      <td>${p.expiresAt}</td>
      <td>
        ${
          valid
            ? html`<form class="inline" method="post" action="/approvals/approve">${csrf}
          <input type="hidden" name="reservationId" value="${p.reservationId}">
          <input type="hidden" name="digest" value="${p.digest}">
          <input type="hidden" name="nonce" value="${p.nonce}">
          <button>Approve</button>
        </form>`
            : null
        }
        <form class="inline" method="post" action="/approvals/reject">${csrf}
          <input type="hidden" name="reservationId" value="${p.reservationId}">
          <input type="hidden" name="nonce" value="${p.nonce}">
          <button>Reject</button>
        </form>
        <br><small><code>${p.reservationId}</code></small>
      </td>
    </tr>`;
  });
  return layout(
    ctx,
    'Approvals',
    html`<p>Transfers above your approval threshold, as stored by the guardian. Each can be approved or
      rejected once. Approving re-checks every limit; it can't override a hard deny.</p>
    ${
      pending.length === 0
        ? html`<p>Nothing is waiting for approval.</p>`
        : html`<table>
          <tr><th>Agent</th><th>Payee</th><th>Amount</th><th>Account</th><th>Policy version</th><th>Expires</th><th></th></tr>
          ${rows}
        </table>`
    }`,
  );
}

export const ACTIVITY_FILTERS = {
  allowed: ['policy.allowed'],
  denied: ['policy.denied'],
  pending: ['policy.require_approval'],
  succeeded: ['transfer.succeeded'],
  unknown: ['transfer.unknown'],
  apps: ['oauth.approved', 'oauth.denied', 'oauth.revoked', 'oauth.refresh_reused'],
} as const satisfies Record<string, readonly AuditEvent['event'][]>;

export type ActivityType = keyof typeof ACTIVITY_FILTERS;

export function activityPage(ctx: PageContext, events: readonly AuditEvent[], type: ActivityType | null): Html {
  const links = [null, ...(Object.keys(ACTIVITY_FILTERS) as ActivityType[])].map((t) =>
    t === type
      ? html`<strong>${t ?? 'all'}</strong> `
      : html`<a href="${t ? `/activity?type=${t}` : '/activity'}">${t ?? 'all'}</a> `,
  );
  const rows = events.map(
    (e) => html`<tr>
      <td>${e.timestamp}</td>
      <td>${e.event}</td>
      <td>${e.tool}</td>
      <td>${e.reasonCode}</td>
      <td><code>${e.reservationId}</code></td>
      <td>${e.policyVersion}</td>
      <td>${Object.entries(e.metadata).map(([k, v]) => html`<code>${k}=${String(v)}</code> `)}</td>
    </tr>`,
  );
  return layout(
    ctx,
    'Activity',
    html`<p>Show: ${links}</p>
    <table>
      <tr><th>Time (UTC)</th><th>Event</th><th>Tool</th><th>Reason</th><th>Reservation</th><th>Policy version</th><th>Details</th></tr>
      ${rows}
    </table>
    ${events.length === 0 ? html`<p>No matching activity.</p>` : null}`,
  );
}

export function stopPage(ctx: PageContext & { csrf: string }, revoked: boolean, unknown: readonly AuditEvent[]): Html {
  return layout(
    ctx,
    'Emergency stop',
    html`${
      revoked
        ? html`<p><strong>Agent stopped.</strong> New calls are denied and pending approvals were rejected.</p>`
        : html`<p><strong>Agent is running.</strong> Stopping denies its new calls and rejects pending approvals immediately.</p>
          <form method="post" action="/stop">
            <input type="hidden" name="csrf" value="${ctx.csrf}">
            <button>Stop the agent</button>
          </form>`
    }
    <h2>Transfers with unknown outcome</h2>
    <p>Stopping does not undo anything: transfers already sent to the bank are not rolled back. A transfer
      whose outcome is unknown keeps its quota held until it is reconciled.
      <a href="/activity?type=unknown">See unknown outcomes in Activity</a>.</p>
    ${
      unknown.length === 0
        ? html`<p>None recorded.</p>`
        : html`<ul>${unknown.map((e) => html`<li>${e.timestamp} <code>${e.reservationId}</code></li>`)}</ul>`
    }`,
  );
}
