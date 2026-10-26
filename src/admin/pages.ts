import { createHash } from 'node:crypto';
import { POLICY_FIELDS, type PolicyFormValues } from './forms.js';
import { Html, html } from './html.js';

export type Mode = 'guard' | 'contain';

// No scripts at all. The one stylesheet is inline and allowed by hash, so the CSP needs
// no 'unsafe-inline' and no route outside the session check.
const CSS = `
body { font: 15px/1.5 system-ui, sans-serif; max-width: 52rem; margin: 0 auto; padding: 1rem; color: #1a1a1a; background: #fff; }
header, .mode { border-bottom: 1px solid #ccc; padding-bottom: .5rem; margin-bottom: 1rem; }
nav a, nav button { margin-right: 1rem; }
nav form { display: inline; }
.mode { background: #fff6d6; padding: .5rem; border: 1px solid #e0c060; }
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
  guard: html`<strong>Guard mode.</strong> mock-bank typed tools protected: every call that goes through kordn is
    checked. Other tools the agent has (a browser, a shell, other apps, hosted agents) are not protected and can
    go around kordn.`,
  contain: html`<strong>Contain mode.</strong> mock-bank typed tools protected: the agent runs in a sandbox with
    no network and kordn is its only way out. Browsers, apps and hosted agents outside the sandbox are not
    protected.`,
};

export interface PageContext {
  mode: Mode;
  agentId: string;
  /** Present when logged in: adds navigation and the logout form. */
  csrf?: string;
  flash?: string | null;
  errors?: readonly string[];
}

export function layout(ctx: PageContext, title: string, body: Html): Html {
  const nav = ctx.csrf
    ? html`<nav>
        <a href="/policy">Policy</a>
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
  version: number;
  values: PolicyFormValues;
}

export function policyPage(ctx: PageContext & { csrf: string }, view: PolicyView): Html {
  return layout(
    ctx,
    'Limits',
    html`<p>Policy <code>${view.policyId}</code>, version ${view.version}, for <code>${view.resourceId}</code>.
      Tighter limits apply to new requests immediately.</p>
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
