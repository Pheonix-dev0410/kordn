import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';

// Helpers for tests that need a real Docker daemon. They only run with KORDN_DOCKER_TESTS=1.
// Every container and image they make is named kordn-test-* so leftovers are identifiable.

export const DOCKER_TESTS = process.env.KORDN_DOCKER_TESTS === '1';
export const ROOT = join(import.meta.dirname, '..');

export const testName = (what: string) => `kordn-test-${what}-${randomBytes(4).toString('hex')}`;

export interface Run {
  code: number | null;
  stdout: string;
  stderr: string;
}

/** Runs docker with an argument array (never a shell string), optionally feeding stdin. */
export function docker(args: string[], input?: string, timeoutMs = 120_000, env?: NodeJS.ProcessEnv): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args, { stdio: ['pipe', 'pipe', 'pipe'], env: env ? { ...process.env, ...env } : process.env });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.setEncoding('utf8').on('data', (d: string) => (stdout += d));
    child.stderr.setEncoding('utf8').on('data', (d: string) => (stderr += d));
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.stdin.end(input ?? '');
  });
}

export async function dockerOk(args: string[], input?: string, timeoutMs?: number, env?: NodeJS.ProcessEnv): Promise<string> {
  const r = await docker(args, input, timeoutMs, env);
  if (r.code !== 0) throw new Error(`docker ${args.join(' ')} failed (${r.code}): ${r.stderr}`);
  return r.stdout;
}

/** Builds sandbox/Dockerfile from the repo root. */
export async function buildSandboxImage(tag: string): Promise<void> {
  await dockerOk(['build', '-q', '-f', join(ROOT, 'sandbox/Dockerfile'), '-t', tag, ROOT], undefined, 600_000);
}

export async function removeImages(...tags: string[]): Promise<void> {
  if (tags.length) await docker(['image', 'rm', '-f', ...tags]);
}

export function hostUser(): string {
  return `${process.getuid?.()}:${process.getgid?.()}`;
}

/** Ensures nothing named kordn-test-* is left by a test run. */
export async function leftovers(): Promise<string[]> {
  const containers = await dockerOk(['ps', '-a', '--filter', 'name=kordn-test-', '--format', '{{.Names}}']);
  return containers.split('\n').filter(Boolean);
}

