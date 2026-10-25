import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { ApprovalError, ApprovalResult, Guardian } from '../guardian-api.js';
import { AgentId } from '../schema.js';
import { Form, POLICY_FIELDS, parseCount, type PolicyFormValues, policyFormValues, readPolicyForm } from './forms.js';
import type { Html } from './html.js';
import {
  ACTIVITY_FILTERS,
  type ActivityType,
  activityPage,
  approvalsPage,
  CSP,
  loginPage,
  type Mode,
  type PageContext,
  policyPage,
  stopPage,
} from './pages.js';
import { SESSION_TTL_MS, type Session, Sessions, WindowLimit, sameSecret, secret } from './session.js';

// Local admin UI (design doc §10). Loopback only, token login, server-side sessions, and a
// CSRF token plus an exact Origin match on every POST. GET never changes state.

export const LOOPBACK = '127.0.0.1';
export const LOGIN_FAILURES_PER_MINUTE = 5;
export const DECISIONS_PER_MINUTE = 30;
const ACTIVITY_LIMIT = 200;
const MAX_BODY_BYTES = 16 * 1024;
const COOKIE = 'kordn_admin';

export interface AdminServerOptions {
  guardian: Guardian;
  /** The agent this UI administers. Stop revokes it. */
  agentId: string;
  /** Decided by the caller from the sandbox checks; shown on every page. */
  mode: Mode;
  /** Only 127.0.0.1 is accepted. */
  host?: string;
  /** 0 (the default) picks a free port. */
  port?: number;
  nowMs?: () => number;
}

export interface AdminServer {
  url: string;
  /** Log-in token. Print it for the user; never log it anywhere else. */
  token: string;
  close(): Promise<void>;
}

interface Request {
  res: ServerResponse;
  url: URL;
  session: Session | null;
  form: Form;
}

type Handler = (r: Request) => Promise<void>;

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

export async function startAdminServer(options: AdminServerOptions): Promise<AdminServer> {
  const host = options.host ?? LOOPBACK;
  if (host !== LOOPBACK) throw new Error(`admin UI binds only to ${LOOPBACK}, refusing ${JSON.stringify(host)}`);
  if (options.mode !== 'guard' && options.mode !== 'contain') throw new Error('admin UI mode must be guard or contain');
  if (!AgentId.safeParse(options.agentId).success) throw new Error('admin UI needs a valid agent id');
  // Browsers omit ":80" from Host and Origin, which would fail the exact-match checks.
  if (options.port === 80) throw new Error('admin UI cannot use port 80; pick another port or 0');

  const { guardian, agentId, mode } = options;
  const now = options.nowMs ?? (() => Date.now());
  const token = secret();
  const sessions = new Sessions(now);
  const loginFailures = new WindowLimit(LOGIN_FAILURES_PER_MINUTE, 60_000, now);
  const decisions = new WindowLimit(DECISIONS_PER_MINUTE, 60_000, now);
  // Filled in once listening; the Host and Origin checks need the real port.
  let origin = '';
  let hostHeader = '';

  const loginContext = (errors?: readonly string[]): PageContext => ({ mode, agentId, errors });

  /** For logged-in pages: reads the revoked state for the banner and consumes the flash. */
  async function userContext(r: Request, errors?: readonly string[]): Promise<PageContext & { csrf: string }> {
    const revoked = await guardian.isRevoked(agentId);
    const session = r.session!;
    const flash = session.flash;
    session.flash = null;
    return { mode, agentId, csrf: session.csrf, flash, errors, revoked };
  }

  async function showPolicy(r: Request, status: number, errors?: string[], values?: PolicyFormValues): Promise<void> {
    const { policy, version } = await guardian.getPolicy();
    const page = policyPage(await userContext(r, errors), {
      policyId: policy.policyId,
      resourceId: policy.resourceId,
      version,
      values: values ?? policyFormValues(policy),
    });
    sendHtml(r.res, status, page);
  }

  async function showApprovals(r: Request, status: number, errors?: string[]): Promise<void> {
    const pending = await guardian.listPending();
    sendHtml(r.res, status, approvalsPage(await userContext(r, errors), pending));
  }

  async function decide(r: Request, kind: 'approve' | 'reject'): Promise<void> {
    // Counted before anything else, so failed and malformed attempts use up the budget too.
    if (decisions.full()) throw new HttpError(429, 'Too many approval decisions. Wait a minute.');
    decisions.add();
    const reservationId = hiddenField(r.form, 'reservationId');
    const nonce = hiddenField(r.form, 'nonce');
    const digest = kind === 'approve' ? hiddenField(r.form, 'digest') : '';
    if (reservationId === null || nonce === null || digest === null) {
      return showApprovals(r, 400, ['This approval form is incomplete. Reload the page.']);
    }
    let result: ApprovalResult;
    if (kind === 'reject') result = await guardian.reject(reservationId, nonce);
    // The guardian re-checks revocation too. Checking here as well means a stopped agent's
    // transfer never reaches approve(), whatever the guardian implementation does.
    else if (await guardian.isRevoked(agentId)) result = { ok: false, code: 'SESSION_REVOKED' };
    else result = await guardian.approve(reservationId, digest, nonce);
    if (!result.ok) {
      const verb = kind === 'approve' ? 'approved' : 'rejected';
      return showApprovals(r, 409, [`Not ${verb}: ${result.code}. ${explainApprovalError(result.code)}`]);
    }
    r.session!.flash = `${kind === 'approve' ? 'Approved' : 'Rejected'} transfer ${reservationId}.`;
    redirect(r.res, '/approvals');
  }

  const routes: Record<string, { GET?: Handler; POST?: Handler }> = {
    '/': {
      GET: async (r) => redirect(r.res, '/approvals'),
    },
    '/login': {
      GET: async (r) => (r.session ? redirect(r.res, '/') : sendHtml(r.res, 200, loginPage(loginContext()))),
      POST: async (r) => {
        // The right token always works, so a local process spamming wrong guesses can't lock
        // the user out of Stop. Only wrong guesses are throttled; the token is 256 bits, so
        // the throttle is belt and braces, not what makes guessing infeasible.
        if (!sameSecret(r.form.one('token'), token)) {
          if (loginFailures.full()) throw new HttpError(429, 'Too many failed logins. Wait a minute.');
          loginFailures.add();
          return sendHtml(r.res, 401, loginPage(loginContext(['Wrong token.'])));
        }
        // Logging in again replaces the current session rather than leaving it valid.
        if (r.session) sessions.delete(r.session.id);
        const session = sessions.create();
        r.res.setHeader(
          'set-cookie',
          `${COOKIE}=${session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}`,
        );
        redirect(r.res, '/');
      },
    },
    '/logout': {
      POST: async (r) => {
        sessions.delete(r.session!.id);
        r.res.setHeader('set-cookie', `${COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`);
        redirect(r.res, '/login');
      },
    },
    '/approvals': {
      GET: (r) => showApprovals(r, 200),
    },
    '/approvals/approve': {
      POST: (r) => decide(r, 'approve'),
    },
    '/approvals/reject': {
      POST: (r) => decide(r, 'reject'),
    },
    '/activity': {
      GET: async (r) => {
        const types = r.url.searchParams.getAll('type');
        const type = types[0] ?? null;
        if (types.length > 1 || (type !== null && !Object.hasOwn(ACTIVITY_FILTERS, type))) {
          throw new HttpError(400, 'Unknown activity filter.');
        }
        const events = await guardian.listActivity(
          type ? { events: [...ACTIVITY_FILTERS[type as ActivityType]], limit: ACTIVITY_LIMIT } : { limit: ACTIVITY_LIMIT },
        );
        sendHtml(r.res, 200, activityPage(await userContext(r), events, type as ActivityType | null));
      },
    },
    '/stop': {
      GET: async (r) => {
        const ctx = await userContext(r);
        const unknown = await guardian.listActivity({ events: ['transfer.unknown'], limit: ACTIVITY_LIMIT });
        sendHtml(r.res, 200, stopPage(ctx, ctx.revoked === true, unknown));
      },
      POST: async (r) => {
        await guardian.revoke(agentId);
        r.session!.flash = 'Agent stopped. New calls are denied and pending approvals were rejected.';
        redirect(r.res, '/stop');
      },
    },
    '/policy': {
      GET: (r) => showPolicy(r, 200),
      POST: async (r) => {
        const values = {} as PolicyFormValues;
        for (const name of [...POLICY_FIELDS.map((f) => f.name), 'payees'] as const) values[name] = r.form.one(name) ?? '';
        const expectedVersion = parseCount(r.form.one('version') ?? '');
        if (expectedVersion === null) return showPolicy(r, 400, ['Reload the page and try again.'], values);

        const { policy } = await guardian.getPolicy();
        const parsed = readPolicyForm(values, policy);
        if (!parsed.ok) return showPolicy(r, 400, parsed.errors, values);
        const result = await guardian.updatePolicy(parsed.policy, expectedVersion);
        if (!result.ok && result.code === 'VERSION_CONFLICT') {
          // Show the newer policy rather than the user's edits, so saving again is a choice
          // made with the current values in view.
          return showPolicy(r, 409, [
            'The policy changed since you loaded it. Nothing was saved. Review the current values below.',
          ]);
        }
        if (!result.ok) return showPolicy(r, 400, ['The guardian rejected this policy.'], values);
        r.session!.flash = `Policy saved (version ${result.version}).`;
        redirect(r.res, '/policy');
      },
    },
  };

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    setSecurityHeaders(res);
    // DNS rebinding: a page on evil.example resolving to 127.0.0.1 still sends its own Host.
    if (req.headers.host !== hostHeader) throw new HttpError(400, 'Bad Host header.');

    const url = new URL(req.url ?? '/', origin);
    const route = Object.hasOwn(routes, url.pathname) ? routes[url.pathname] : undefined;
    if (!route) throw new HttpError(404, 'Not found.');
    const method = req.method === 'GET' || req.method === 'POST' ? req.method : null;
    const handler = method ? route[method] : undefined;
    if (!handler) {
      res.setHeader('allow', Object.keys(route).join(', '));
      throw new HttpError(405, 'Method not allowed.');
    }

    const session = sessionFrom(req);
    const isLogin = url.pathname === '/login';
    let form = new Form(new URLSearchParams());
    if (method === 'POST') {
      // Browsers send Origin on every POST. Missing, "null" or another port all fail.
      if (req.headers.origin !== origin) throw new HttpError(403, 'Bad Origin.');
      if (!session && !isLogin) throw new HttpError(403, 'Log in first.');
      form = await readForm(req);
      // The login form has no session yet; the token itself is the secret it proves.
      if (!isLogin && !sameSecret(form.one('csrf'), session!.csrf)) throw new HttpError(403, 'Bad CSRF token.');
    } else if (!session && !isLogin) {
      return redirect(res, '/login');
    }
    await handler({ res, url, session, form });
  }

  function sessionFrom(req: IncomingMessage): Session | null {
    for (const part of (req.headers.cookie ?? '').split(';')) {
      const [name, value] = part.trim().split('=', 2);
      if (name === COOKIE && value) {
        const session = sessions.get(value);
        if (session) return session;
      }
    }
    return null;
  }

  const server = createServer({ requestTimeout: 10_000, headersTimeout: 5_000 }, (req, res) => {
    handle(req, res).catch((err: unknown) => {
      // Guardian failures fail closed with a generic message; details stay server-side.
      const status = err instanceof HttpError ? err.status : 503;
      const message = err instanceof HttpError ? err.message : 'The guardian is unavailable. Nothing was changed.';
      if (res.headersSent) return res.destroy();
      res.statusCode = status;
      res.setHeader('content-type', 'text/plain; charset=utf-8');
      res.end(message + '\n');
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(options.port ?? 0, LOOPBACK, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const { port } = server.address() as AddressInfo;
  hostHeader = `${LOOPBACK}:${port}`;
  origin = `http://${hostHeader}`;

  return {
    url: `${origin}/`,
    token,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections();
      }),
  };
}

function setSecurityHeaders(res: ServerResponse): void {
  res.setHeader('content-security-policy', CSP);
  res.setHeader('x-content-type-options', 'nosniff');
  // Not no-referrer: with no-referrer, browsers send "Origin: null" on same-origin form
  // POSTs (Fetch spec), which the Origin check must reject. same-origin leaks nothing
  // to other sites and keeps the real Origin on our own forms.
  res.setHeader('referrer-policy', 'same-origin');
  res.setHeader('cache-control', 'no-store');
  res.setHeader('x-frame-options', 'DENY');
  res.setHeader('cross-origin-opener-policy', 'same-origin');
  res.setHeader('cross-origin-resource-policy', 'same-origin');
}

function sendHtml(res: ServerResponse, status: number, page: Html): void {
  res.statusCode = status;
  res.setHeader('content-type', 'text/html; charset=utf-8');
  res.end(page.value);
}

function redirect(res: ServerResponse, location: string): void {
  res.statusCode = 303;
  res.setHeader('location', location);
  res.end();
}

async function readForm(req: IncomingMessage): Promise<Form> {
  const type = (req.headers['content-type'] ?? '').split(';')[0]!.trim().toLowerCase();
  if (type !== 'application/x-www-form-urlencoded') throw new HttpError(415, 'Expected a form.');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req as AsyncIterable<Buffer>) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) throw new HttpError(413, 'Form too large.');
    chunks.push(chunk);
  }
  return new Form(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
}

/** A required hidden field: present once, 1 to 256 characters. */
function hiddenField(form: Form, name: string): string | null {
  const value = form.one(name);
  return value !== null && value.length >= 1 && value.length <= 256 ? value : null;
}

function explainApprovalError(code: ApprovalError): string {
  switch (code) {
    case 'NOT_PENDING':
      return 'It is no longer pending: already decided, expired or stopped.';
    case 'STALE_DIGEST':
      return 'The transfer details no longer match what was shown. Reload the page.';
    case 'BAD_NONCE':
      return 'This approval form was already used or is out of date. Reload the page.';
    case 'APPROVAL_EXPIRED':
      return 'The approval window has passed.';
    case 'SESSION_REVOKED':
      return 'The agent is stopped.';
    default:
      return 'A policy limit now blocks this transfer.';
  }
}
