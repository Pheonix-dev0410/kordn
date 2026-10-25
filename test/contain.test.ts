import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from '../src/fake-guardian.js';
import { formatReport, runContain, startCanary } from '../src/sandbox.js';
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
