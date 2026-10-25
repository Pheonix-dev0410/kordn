import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Guardian } from '../guardian-api.js';
import { AgentId } from '../schema.js';
import { Form, POLICY_FIELDS, parseCount, type PolicyFormValues, policyFormValues, readPolicyForm } from './forms.js';
import type { Html } from './html.js';
import { CSP, loginPage, type Mode, type PageContext, policyPage } from './pages.js';
import { SESSION_TTL_MS, type Session, Sessions, WindowLimit, sameSecret, secret } from './session.js';

// Local admin UI (design doc §10). Loopback only, token login, server-side sessions, and a
// CSRF token plus an exact Origin match on every POST. GET never changes state.

export const LOOPBACK = '127.0.0.1';
export const LOGIN_FAILURES_PER_MINUTE = 5;
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

  const { guardian, agentId, mode } = options;
  const now = options.nowMs ?? (() => Date.now());
  const token = secret();
  const sessions = new Sessions(now);
  const loginFailures = new WindowLimit(LOGIN_FAILURES_PER_MINUTE, 60_000, now);
  // Filled in once listening; the Host and Origin checks need the real port.
  let origin = '';
  let hostHeader = '';

  const pageContext = (session: Session | null, errors?: readonly string[]): PageContext => {
    const flash = session?.flash ?? null;
    if (session) session.flash = null;
    return { mode, agentId, csrf: session?.csrf, flash, errors };
  };

  async function showPolicy(r: Request, status: number, errors?: string[], values?: PolicyFormValues): Promise<void> {
    const { policy, version } = await guardian.getPolicy();
    const session = r.session!;
    const page = policyPage(
      { ...pageContext(session, errors), csrf: session.csrf },
      { policyId: policy.policyId, resourceId: policy.resourceId, version, values: values ?? policyFormValues(policy) },
    );
    sendHtml(r.res, status, page);
  }

  const routes: Record<string, { GET?: Handler; POST?: Handler }> = {
    '/': {
      GET: async (r) => redirect(r.res, '/policy'),
    },
    '/login': {
      GET: async (r) => (r.session ? redirect(r.res, '/') : sendHtml(r.res, 200, loginPage(pageContext(null)))),
      POST: async (r) => {
        // Checked before the token so a locked-out guesser learns nothing, even when right.
        if (loginFailures.full()) throw new HttpError(429, 'Too many failed logins. Wait a minute.');
        if (!sameSecret(r.form.one('token'), token)) {
          loginFailures.add();
          return sendHtml(r.res, 401, loginPage(pageContext(null, ['Wrong token.'])));
        }
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
