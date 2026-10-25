import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { formatReport, runContain, staleContainers, startCanary } from '../src/sandbox.js';
import { CHECK_IDS } from '../src/sandbox-checks.js';
import { Policy } from '../src/schema.js';

// runContain without Docker. The Docker paths are in test/contain-docker.test.ts.

const policy = Policy.parse(policyJson);
const guardian = () => createFakeGuardian({ policy });
const base = { agentId: policy.agentId, image: 'kordn-sandbox', docker: '/nonexistent/docker', onReport: () => {} };

describe('runContain', () => {
  for (const platform of ['darwin', 'win32', 'freebsd'] as const) {
    it(`refuses on ${platform} before touching Docker`, async () => {
      await expect(runContain({ ...base, guardian: guardian(), platform })).rejects.toThrow(
        new RegExp(`Contain mode is not supported on ${platform}`),
      );
    });
  }

  it('fails clearly when Docker is not available, leaving no socket behind', async () => {
    const before = readdirSync(tmpdir()).filter((d) => d.startsWith('kordn-test-runner-'));
    await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', name: 'kordn-test-runner-x' })).rejects.toThrow(
      /Docker is not available/,
    );
    expect(readdirSync(tmpdir()).filter((d) => d.startsWith('kordn-test-runner-'))).toEqual(before);
  });

  it('rejects container names docker would not accept as a plain name', async () => {
    for (const name of ['--privileged', 'a b', '', '../x']) {
      await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', name })).rejects.toThrow(/container name/);
    }
  });
});

describe('startCanary', () => {
  it('listens on host loopback and counts connections', async () => {
    const canary = await startCanary();
    try {
      await new Promise<void>((resolve) => {
        const s = connect(canary.port, '127.0.0.1');
        s.on('close', () => resolve());
        s.on('error', () => resolve());
      });
      expect(canary.hits()).toBe(1);
    } finally {
      await canary.close();
    }
  });
});

describe('formatReport', () => {
  const checks = CHECK_IDS.map((id) => ({ id, pass: true, detail: `${id} ok` }));

  it('labels Contain when every check passed', () => {
    const text = formatReport({ mode: 'contain', platform: 'linux', imageId: 'sha256:abc', checks });
    expect(text).toMatch(/^kordn contain: CONTAIN mode/);
    expect(text).toContain('sha256:abc');
    expect(text).not.toContain('FAIL');
  });

  it('labels Guard and lists every failing check with its reason', () => {
    const failed = checks.map((c) =>
      c.id === 'rootless' || c.id === 'network' ? { ...c, pass: false, detail: `${c.id} broken` } : c,
    );
    const text = formatReport({ mode: 'guard', platform: 'linux', imageId: null, checks: failed });
    expect(text).toMatch(/^kordn contain: GUARD mode/);
    expect(text).toMatch(/FAIL\s+rootless\s+rootless broken/);
    expect(text).toMatch(/FAIL\s+network\s+network broken/);
    expect(text).toMatch(/2 isolation checks failed/);
  });
});

describe('runContain with a fake docker CLI', () => {
  it("refuses a container name that is already in use, and never removes someone else's container", async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
    const log = join(dir, 'docker.log');
    process.env.FAKE_DOCKER_LOG = log;
    try {
      const docker = join(import.meta.dirname, 'fixtures/fake-docker.mjs');
      await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', docker, name: 'taken' })).rejects.toThrow(
        /container name taken is already in use/,
      );
      const calls = readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)[0]);
      expect(calls).not.toContain('rm');
      expect(calls).not.toContain('run');
    } finally {
      delete process.env.FAKE_DOCKER_LOG;
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('runContain lifecycle (fake docker CLI)', () => {
  const fakeDocker = join(import.meta.dirname, 'fixtures/fake-docker.mjs');
  const containerId = 'c'.repeat(64);

  async function withFakeDocker<T>(env: Record<string, string>, fn: (calls: () => string[][]) => Promise<T>): Promise<T> {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
    const log = join(dir, 'docker.log');
    Object.assign(process.env, { FAKE_DOCKER_LOG: log, ...env });
    try {
      return await fn(() => readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)));
    } finally {
      for (const k of ['FAKE_DOCKER_LOG', ...Object.keys(env)]) delete process.env[k];
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('runs the image by its resolved ID, labels the container, then uses the container ID, and never hangs on an open connection', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow' }, async (calls) => {
      const result = await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, name: 'kordn-test-flow' });
      expect(result.report.mode).toBe('guard');
      expect(result.agent).toEqual({ exitCode: 0, stdout: 'agent ran\n', stderr: '' });

      const log = calls();
      const run = log.find((c) => c[0] === 'run') ?? [];
      expect(run).toContain(`sha256:${'a'.repeat(64)}`);
      expect(run).not.toContain('kordn-sandbox');
      expect(run).toEqual(expect.arrayContaining(['--label', `kordn.contain=${process.pid}`]));
      expect(run.some((a) => /^kordn\.contain\.session=[0-9a-f]{16}$/.test(a))).toBe(true);

      const after = log.slice(log.indexOf(run) + 1).filter((c) => ['inspect', 'exec', 'rm'].includes(c[0] ?? ''));
      expect(after.map((c) => c[0])).toEqual(['inspect', 'exec', 'exec', 'rm']);
      for (const c of after) {
        expect(c).toContain(containerId);
        expect(c).not.toContain('kordn-test-flow');
      }
    });
  });

  it('warns when the container cannot be removed', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_RM_FAIL: '1' }, async () => {
      const warnings: string[] = [];
      const onWarning = (w: Error) => warnings.push(w.message);
      process.on('warning', onWarning);
      try {
        await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, name: 'kordn-test-rmfail' });
        await new Promise((r) => setImmediate(r));
      } finally {
        process.off('warning', onWarning);
      }
      expect(warnings).toEqual([expect.stringMatching(/could not remove container c{64}.*removal failed/)]);
    });
  });

  it('rejects an image reference that could be read as a flag or is not a plain reference', async () => {
    for (const image of ['-v', '--privileged', '', 'a b', 'kordn\nsandbox', '../x', 'x;rm']) {
      await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', image })).rejects.toThrow(/invalid image reference/);
    }
  });
});

describe('staleContainers', () => {
  it('picks containers whose launching process is gone, and leaves unknown labels alone', () => {
    const ps = 'aaa 100\nbbb 200\nccc notapid\nddd\n';
    expect(staleContainers(ps, (pid) => pid === 100)).toEqual(['bbb']);
  });
});
