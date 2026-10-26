import { request } from 'node:http';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { startAdminServer, type AdminServer, type AdminServerOptions } from '../src/admin/server.js';
import { createFakeGuardian } from './fake-guardian.js';
import type { Guardian } from '../src/guardian-api.js';
import { Policy } from '../src/schema.js';

export const policy = Policy.parse(policyJson);
export const agent = policy.agentId;

export interface Reply {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

export interface SendOptions {
  headers?: Record<string, string>;
  /** Form fields, sent urlencoded. */
  form?: Record<string, string> | URLSearchParams;
  body?: string;
}

/** Raw HTTP so tests control Host, Origin and Cookie exactly. */
export function send(server: AdminServer, method: string, path: string, options: SendOptions = {}): Promise<Reply> {
  const { port } = new URL(server.url);
  const body =
    options.body ?? (options.form ? new URLSearchParams(options.form as Record<string, string>).toString() : undefined);
  const headers: Record<string, string> = { host: `127.0.0.1:${port}`, ...options.headers };
  if (options.form && !headers['content-type']) headers['content-type'] = 'application/x-www-form-urlencoded';
  return new Promise((resolve, reject) => {
    const req = request({ host: '127.0.0.1', port: Number(port), method, path, headers }, (res) => {
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (data += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

export const originOf = (server: AdminServer) => new URL(server.url).origin;

export function csrfFrom(body: string): string {
  const match = /name="csrf" value="([^"]+)"/.exec(body);
  if (!match) throw new Error('no csrf token in page');
  return match[1]!;
}

export interface Session {
  cookie: string;
  csrf: string;
  get(path: string): Promise<Reply>;
  /** A same-origin form POST with the session's CSRF token. */
  post(path: string, form?: Record<string, string>, headers?: Record<string, string>): Promise<Reply>;
}

export async function login(server: AdminServer): Promise<Session> {
  const res = await send(server, 'POST', '/login', { form: { token: server.token }, headers: { origin: originOf(server) } });
  if (res.status !== 303) throw new Error(`login failed: ${res.status}`);
  const setCookie = [res.headers['set-cookie'] ?? []].flat()[0] ?? '';
  const cookie = setCookie.split(';')[0]!;
  const page = await send(server, 'GET', '/policy', { headers: { cookie } });
  const csrf = csrfFrom(page.body);
  return {
    cookie,
    csrf,
    get: (path) => send(server, 'GET', path, { headers: { cookie } }),
    post: (path, form = {}, headers = {}) =>
      send(server, 'POST', path, { form: { csrf, ...form }, headers: { cookie, origin: originOf(server), ...headers } }),
  };
}

export async function start(
  options: Partial<AdminServerOptions> = {},
): Promise<{ server: AdminServer; guardian: Guardian }> {
  const guardian = options.guardian ?? createFakeGuardian({ policy });
  const server = await startAdminServer({ guardian, agentId: agent, mode: 'guard', ...options });
  return { server, guardian };
}
