import { createHash } from 'node:crypto';
import { Html, html } from '../admin/html.js';

// No scripts. The one stylesheet is inline and allowed by hash, as on the admin pages.
const CSS = `
body { font: 16px/1.5 system-ui, sans-serif; max-width: 30rem; margin: 0 auto; padding: 1rem; color: #1a1a1a; background: #fff; }
h1 { font-size: 1.4rem; }
.error { background: #fde2e2; padding: .5rem; }
label { display: block; margin-top: 1rem; font-weight: 600; }
input[type=password] { width: 100%; box-sizing: border-box; font: inherit; padding: .5rem; }
.actions { margin-top: 1rem; display: flex; gap: .75rem; }
button { font: inherit; padding: .6rem 1.2rem; }
strong { word-break: break-all; }
`;

// Trusted constant, inserted unescaped so the bytes match the CSP hash.
const STYLE = new Html(CSS);
const STYLE_SRC = `style-src 'sha256-${createHash('sha256').update(CSS).digest('base64')}'`;

// Only a bare http(s) origin is emitted, so a value can't add directives or sources.
const ORIGIN = /^https?:\/\/[A-Za-z0-9.-]+(:\d{1,5})?$|^https?:\/\/\[[0-9A-Fa-f:]+\](:\d{1,5})?$/;

/** form-action lists the redirect origin too: Chrome checks redirects that follow a form POST. */
export function consentCsp(redirectOrigin?: string): string {
  const formAction = redirectOrigin !== undefined && ORIGIN.test(redirectOrigin) ? `'self' ${redirectOrigin}` : "'self'";
  return ["default-src 'none'", STYLE_SRC, `form-action ${formAction}`, "frame-ancestors 'none'", "base-uri 'none'"].join('; ');
}

function layout(title: string, body: Html): Html {
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${title}</title>
<style>${STYLE}</style>
</head>
<body>
${body}
</body>
</html>`;
}

export interface ConsentView {
  clientName: string;
  redirectHost: string;
  requestId: string;
  csrf: string;
  errors?: readonly string[];
}

export function consentPage(view: ConsentView): Html {
  const errors = view.errors?.length
    ? html`<div class="error" role="alert"><ul>${view.errors.map((e) => html`<li>${e}</li>`)}</ul></div>`
    : null;
  return layout(
    'Connect to kordn',
    html`<h1>An app wants to use kordn</h1>
${errors}
<p>It says it is <strong>${view.clientName}</strong></p>
<p>After approval you'll be sent to <strong>${view.redirectHost}</strong>: check that this is the app you just started connecting.</p>
<form method="post">
<input type="hidden" name="request" value="${view.requestId}">
<input type="hidden" name="csrf" value="${view.csrf}">
<label for="owner_token">KORDN_TOKEN</label>
<input type="password" id="owner_token" name="owner_token" autocomplete="off" required>
<div class="actions">
<button type="submit" name="decision" value="approve">Approve</button>
<button type="submit" name="decision" value="deny" formnovalidate>Deny</button>
</div>
</form>`,
  );
}

/** For bad client_id / redirect_uri and other failures that can't redirect. Fixed text only. */
export function oauthErrorPage(message: string): Html {
  return layout('kordn', html`<h1>Can't connect</h1>
<div class="error" role="alert">${message}</div>`);
}
