import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { login } from './admin-helpers.js';
import { buildSandboxImage, DOCKER_TESTS, dockerOk, removeImages, ROOT, testName } from './docker.js';

// kordn contain --admin end to end against a real Docker daemon and the real sandbox image.

const cli = join(ROOT, 'dist', 'index.js');
const image = testName('cli');
const dirs: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  return dir;
}

describe.skipIf(!DOCKER_TESTS)('kordn contain against Docker', () => {
  beforeAll(async () => {
    await buildSandboxImage(image);
  }, 900_000);

  afterAll(async () => {
    await removeImages(image);
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
  }, 120_000);

  it('reports Guard, serves the admin UI while the agent runs, and exits with the agent', async () => {
    const runtime = tempDir();
    chmodSync(runtime, 0o700);
    const tmp = tempDir();
    // The default agent, started late so the admin UI can be checked while it runs.
    const agent = ['/nodejs/bin/node', '-e', "setTimeout(() => import('/app/sandbox/agent.mjs'), 4000)"];
    const child = spawn(process.execPath, [cli, 'contain', '--image', image, '--admin', '--', ...agent], {
      // The whole environment, so docker finds the same daemon (DOCKER_HOST, docker context) as the tests.
      env: { ...process.env, XDG_RUNTIME_DIR: runtime, XDG_STATE_HOME: tempDir(), XDG_CONFIG_HOME: tempDir(), TMPDIR: tmp },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => (stdout += d));
    child.stderr.on('data', (d) => (stderr += d));
    const exited = new Promise<number | null>((done) => child.on('close', done));
    try {
      const adminFile = join(runtime, 'kordn', `admin-${child.pid}.json`);
      const until = async (done: () => boolean) => {
        const deadline = Date.now() + 90_000;
        while (!done() && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
      };
      // The admin UI starts before the checks, so they can probe its real port.
      await until(() => existsSync(adminFile));
      expect(existsSync(adminFile), stderr).toBe(true);
      const file = JSON.parse(readFileSync(adminFile, 'utf8')) as { url: string; token: string };
      const session = await login({ url: file.url, token: file.token, close: async () => {} });

      await until(() => stderr.includes('admin UI: guard mode'));
      expect(stderr).toMatch(/^kordn contain: GUARD mode \(linux, image sha256:[0-9a-f]{64}\)$/m);
      expect(stderr).toMatch(/FAIL\s+rootless/);
      // The checks probed the real admin UI port and couldn't reach it.
      expect(stderr).toMatch(new RegExp(`ok\\s+hostServicesUnreachable\\s+.*admin UI port ${new URL(file.url).port}`));
      const page = await session.get('/approvals');
      expect(page.status).toBe(200);
      expect(page.body).toContain('Guard mode.');

      expect(await exited, stderr).toBe(0);
      // Every line the agent printed is shown prefixed.
      const lines = stdout.split('\n').filter(Boolean);
      expect(lines.length).toBeGreaterThan(0);
      expect(lines.every((l) => l.startsWith('agent | '))).toBe(true);
      const steps = lines.map((l) => JSON.parse(l.slice('agent | '.length)) as Record<string, unknown>);
      expect(steps.find((s) => s.step === 'tools/call')).toMatchObject({ tool: 'af_get_balance', isError: false });
      expect(existsSync(adminFile)).toBe(false);
      await expect(fetch(file.url)).rejects.toThrow();
      // Cleaned up: no container labelled with this launcher's pid, no socket directory.
      expect(await dockerOk(['ps', '--all', '--quiet', '--filter', `label=kordn.contain=${child.pid}`])).toBe('');
      expect(readdirSync(tmp)).toEqual([]);
    } finally {
      child.kill('SIGKILL');
    }
  }, 300_000);
});
