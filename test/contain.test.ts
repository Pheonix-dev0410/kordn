import { existsSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, rmSync } from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import policyJson from '../examples/policy.json' with { type: 'json' };
import { createFakeGuardian } from './fake-guardian.js';
import { assertContainPlatform, formatReport, launcherIdentity, processStart, runContain, staleContainers, startCanary } from '../src/sandbox.js';
import { CHECK_IDS } from '../src/sandbox-checks.js';
import { Policy } from '../src/schema.js';

// runContain without Docker. The Docker paths are in test/contain-docker.test.ts.

const policy = Policy.parse(policyJson);
const guardian = () => createFakeGuardian({ policy });

/** A sink that keeps what the agent wrote, and calls onText after each chunk. */
function collector(onText: (text: string) => void = () => {}) {
  let text = '';
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      text += chunk.toString('utf8');
      onText(text);
      done();
    },
  });
  return { sink, text: () => text };
}
const discard = () => collector().sink;
const base = {
  agentId: policy.agentId,
  image: 'kordn-sandbox',
  docker: '/nonexistent/docker',
  onReport: () => {},
  agentOutput: { stdout: discard(), stderr: discard() },
};

describe('runContain', () => {
  for (const platform of ['darwin', 'win32', 'freebsd'] as const) {
    it(`refuses on ${platform} before touching Docker`, async () => {
      await expect(runContain({ ...base, guardian: guardian(), platform })).rejects.toThrow(
        new RegExp(`Contain mode is not supported on ${platform}`),
      );
    });
  }

  it('exposes the platform check so a caller can refuse before touching Docker', () => {
    expect(() => assertContainPlatform('darwin')).toThrow(
      'Contain mode is not supported on darwin: it needs Linux with (rootless) Docker. Use Guard mode instead.',
    );
    expect(() => assertContainPlatform('linux')).not.toThrow();
  });

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

// These read /proc (boot id, namespaces), so they only run on Linux.
describe.runIf(process.platform === 'linux')('runContain lifecycle (fake docker CLI)', () => {
  const fakeDocker = join(import.meta.dirname, 'fixtures/fake-docker.mjs');
  const containerId = 'c'.repeat(64);

  async function withFakeDocker<T>(env: Record<string, string>, fn: (calls: () => string[][]) => Promise<T>): Promise<T> {
    const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
    const log = join(dir, 'docker.log');
    Object.assign(process.env, { FAKE_DOCKER_LOG: log, ...env });
    try {
      // No log yet means docker was never called.
      const read = () => (existsSync(log) ? readFileSync(log, 'utf8') : '');
      return await fn(() => read().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
    } finally {
      for (const k of ['FAKE_DOCKER_LOG', ...Object.keys(env)]) delete process.env[k];
      rmSync(dir, { recursive: true, force: true });
    }
  }

  it('runs the image by its resolved ID, labels the container, then uses the container ID, and never hangs on an open connection', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow' }, async (calls) => {
      const out = collector();
      const err = collector();
      const result = await runContain({
        ...base,
        guardian: guardian(),
        platform: 'linux',
        docker: fakeDocker,
        name: 'kordn-test-flow',
        agentOutput: { stdout: out.sink, stderr: err.sink },
      });
      expect(result.report.mode).toBe('guard');
      expect(result.agent).toEqual({ exitCode: 0, signal: null, timedOut: false, outputBytes: 10, truncated: false });
      expect(out.text()).toBe('agent | agent ran\n');
      expect(err.text()).toBe('');

      const log = calls();
      const run = log.find((c) => c[0] === 'run') ?? [];
      expect(run).toContain(`sha256:${'a'.repeat(64)}`);
      expect(run).not.toContain('kordn-sandbox');
      const me = launcherIdentity();
      for (const label of [`kordn.contain=${me.pid}`, `kordn.contain.boot=${me.boot}`, `kordn.contain.pidns=${me.pidns}`, `kordn.contain.start=${me.start}`]) {
        expect(run).toEqual(expect.arrayContaining(['--label', label]));
      }
      expect(run.some((a) => /^kordn\.contain\.session=[0-9a-f]{16}$/.test(a))).toBe(true);

      const after = log.slice(log.indexOf(run) + 1).filter((c) => ['inspect', 'exec', 'rm'].includes(c[0] ?? ''));
      expect(after.map((c) => c[0])).toEqual(['inspect', 'exec', 'exec', 'rm']);
      for (const c of after) {
        expect(c).toContain(containerId);
        expect(c).not.toContain('kordn-test-flow');
      }
    });
  });

  it('waits for an async onReport before starting the agent, and cleans up if it fails', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow' }, async (calls) => {
      const agentExecs = () => calls().filter((c) => c[0] === 'exec' && !c.includes('--input-type=module')).length;
      let execsDuringReport = -1;
      await runContain({
        ...base,
        guardian: guardian(),
        platform: 'linux',
        docker: fakeDocker,
        onReport: async () => {
          await new Promise((r) => setTimeout(r, 200));
          execsDuringReport = agentExecs();
        },
      });
      expect(execsDuringReport).toBe(0);
      expect(agentExecs()).toBe(1);

      const before = calls().length;
      await expect(
        runContain({
          ...base,
          guardian: guardian(),
          platform: 'linux',
          docker: fakeDocker,
          onReport: async () => {
            await new Promise((r) => setTimeout(r, 10));
            throw new Error('admin UI failed to start');
          },
        }),
      ).rejects.toThrow(/admin UI failed to start/);
      const second = calls().slice(before);
      expect(second.filter((c) => c[0] === 'exec').map((c) => c.includes('--input-type=module'))).toEqual([true]);
      expect(second.at(-1)).toEqual(['rm', '--force', containerId]);
    });
  });

  it('streams the agent output as it arrives, before the agent exits', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'hang' }, async (calls) => {
      const controller = new AbortController();
      let settled = false;
      let seenWhileRunning = false;
      const out = collector((text) => {
        if (!text.includes('agent started')) return;
        seenWhileRunning = !settled;
        controller.abort();
      });
      await expect(
        runContain({
          ...base,
          guardian: guardian(),
          platform: 'linux',
          docker: fakeDocker,
          signal: controller.signal,
          agentOutput: { stdout: out.sink, stderr: discard() },
        }).finally(() => (settled = true)),
      ).rejects.toThrow(expect.objectContaining({ name: 'AbortError' }));
      expect(seenWhileRunning).toBe(true);
      expect(calls().at(-1)).toEqual(['rm', '--force', containerId]);
    });
  });

  it('caps the agent output: drops the rest with one notice, keeps reading, and still cleans up', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_AGENT_BYTES: String(4 * 1024 * 1024) }, async (calls) => {
      const out = collector();
      const err = collector();
      const result = await runContain({
        ...base,
        guardian: guardian(),
        platform: 'linux',
        docker: fakeDocker,
        agentOutputLimitBytes: 1000,
        agentOutput: { stdout: out.sink, stderr: err.sink },
      });
      // The agent wasn't blocked on a full pipe: it got to exit normally.
      expect(result.agent).toEqual({
        exitCode: 0,
        signal: null,
        timedOut: false,
        outputBytes: 4 * 1024 * 1024 + 'agent ran\n'.length,
        truncated: true,
      });
      // The cap counts the agent's raw bytes; the prefixes kordn adds don't count.
      expect(out.text()).toBe(`agent | agent ran\nagent | ${'x'.repeat(1000 - 'agent ran\n'.length)}\n`);
      // The notice is kordn's own line, unprefixed.
      expect(err.text()).toBe("kordn: the agent's output passed 1000 bytes; dropping the rest\n");
      expect(calls().at(-1)).toEqual(['rm', '--force', containerId]);
    });
  });

  it('starts every agent line prefixed even when stdout and stderr interleave on one terminal (2>&1)', async () => {
    const chunks = [
      ['out', 'a'],
      ['err', 'b\n'],
      ['out', 'kordn contain: CONTAIN mode (linux, image sha256:x)\n'],
      ['err', 'c'],
      ['out', 'd'],
      ['err', 'e\n'],
    ].map(([stream, data]) => [stream, Buffer.from(data!).toString('base64')]);
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(chunks) }, async () => {
      const terminal = collector();
      await runContain({
        ...base,
        guardian: guardian(),
        platform: 'linux',
        docker: fakeDocker,
        agentOutput: { stdout: terminal.sink, stderr: terminal.sink },
      });
      expect(terminal.text()).toBe(
        [
          'agent | a',
          'agent! | b',
          'agent | kordn contain: CONTAIN mode (linux, image sha256:x)',
          'agent! | c',
          'agent | d',
          'agent! | e',
          '',
        ].join('\n'),
      );
    });
  });

  it('shows agent output inert and prefixed, a line at a time, across chunks', async () => {
    const chunks = [
      ['out', 'kordn contain: CONTAIN mode (linux, image sha256:x)\n'],
      ['out', '\x1b[1A\x1b[2K\x1b]52;c;aGVsbG8=\x07\x1b]0;title\x07GUARD\rCONTAIN\n'],
      ['err', 'warn'],
      ['out', Buffer.from('🦊').subarray(0, 2)],
      ['err', 'ing\n'],
      ['out', Buffer.from('🦊').subarray(2)],
      ['out', ' done'],
    ].map(([stream, data]) => [stream, Buffer.from(data as string | Buffer).toString('base64')]);
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(chunks) }, async () => {
      const out = collector();
      const err = collector();
      await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, agentOutput: { stdout: out.sink, stderr: err.sink } });
      expect(out.text()).toBe(
        'agent | kordn contain: CONTAIN mode (linux, image sha256:x)\nagent | [1A[2K]52;c;aGVsbG8=]0;titleGUARDCONTAIN\nagent | 🦊 done\n',
      );
      expect(err.text()).toBe('agent! | warning\n');
    });
  });

  it('tells a timeout from a docker exec killed by a signal', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'hang' }, async () => {
      const result = await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, agentTimeoutMs: 300 });
      expect(result.agent).toMatchObject({ exitCode: null, signal: 'SIGTERM', timedOut: true });
    });
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_AGENT_SIGNAL: 'SIGKILL' }, async () => {
      const result = await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker });
      expect(result.agent).toMatchObject({ exitCode: null, signal: 'SIGKILL', timedOut: false });
    });
  });

  it('a stdout sink that fails is reported once on stderr, and breaks neither the run nor its cleanup', async () => {
    const chunks = [
      ['err', 'half a '],
      ['out', 'one\n'],
      ['err', 'line\n'],
      ['out', 'two\n'],
    ].map(([stream, data]) => [stream, Buffer.from(data!).toString('base64')]);
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow', FAKE_DOCKER_AGENT_CHUNKS: JSON.stringify(chunks) }, async (calls) => {
      const broken = new Writable({ write: (_chunk, _encoding, done) => done(new Error('EPIPE')) });
      const err = collector();
      const result = await runContain({
        ...base,
        guardian: guardian(),
        platform: 'linux',
        docker: fakeDocker,
        agentOutput: { stdout: broken, stderr: err.sink },
      });
      expect(result.agent?.exitCode).toBe(0);
      // The notice is a kordn line of its own, even when it comes in the middle of an agent line.
      expect(err.text()).toBe("agent! | half a \nkordn: stdout closed; dropping the agent's stdout\nagent! | line\n");
      expect(calls().at(-1)).toEqual(['rm', '--force', containerId]);
    });
  });

  it('notices a sink that fails in a later run too', async () => {
    let closed = false;
    const stdout = new Writable({
      write(_chunk, _encoding, done) {
        done();
        // Like a pipe whose reader went away: the error comes as an event, not through the write.
        if (closed) this.destroy(new Error('EPIPE'));
      },
    });
    for (const run of [1, 2]) {
      closed = run === 2;
      await withFakeDocker({ FAKE_DOCKER_MODE: 'flow' }, async () => {
        const err = collector();
        await runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, agentOutput: { stdout, stderr: err.sink } });
        await new Promise((r) => setImmediate(r));
        expect(err.text(), `run ${run}`).toBe(run === 1 ? '' : "kordn: stdout closed; dropping the agent's stdout\n");
      });
    }
  });

  it('stops a running agent when the signal aborts, and still cleans up everything', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'hang' }, async (calls) => {
      const controller = new AbortController();
      const started = Date.now();
      await expect(
        runContain({
          ...base,
          guardian: guardian(),
          platform: 'linux',
          docker: fakeDocker,
          name: 'kordn-test-abort',
          signal: controller.signal,
          onReport: () => void setTimeout(() => controller.abort(), 200),
        }),
      ).rejects.toThrow(expect.objectContaining({ name: 'AbortError' }));
      expect(Date.now() - started).toBeLessThan(10_000);
      expect(calls().at(-1)).toEqual(['rm', '--force', containerId]);
      expect(readdirSync(tmpdir()).filter((d) => d.startsWith('kordn-test-abort-'))).toEqual([]);
    });
  });

  it('does not start when the signal is already aborted', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'flow' }, async (calls) => {
      await expect(
        runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, signal: AbortSignal.abort() }),
      ).rejects.toThrow(expect.objectContaining({ name: 'AbortError' }));
      expect(calls().map((c) => c[0])).not.toContain('run');
    });
  });

  it('after an abort during docker run, sweeps for the session container like after a timeout', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'slowrun' }, async (calls) => {
      const signal = AbortSignal.timeout(300);
      await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, signal })).rejects.toThrow();
      const sweeps = calls().filter((c) => c[0] === 'ps' && c.some((a) => a.startsWith('label=kordn.contain.session=')));
      expect(sweeps).toHaveLength(2);
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

  it('after a docker run timeout, sweeps for the session container again once it may have been created', async () => {
    await withFakeDocker({ FAKE_DOCKER_MODE: 'slowrun' }, async (calls) => {
      await expect(
        runContain({ ...base, guardian: guardian(), platform: 'linux', docker: fakeDocker, name: 'kordn-test-slow', runTimeoutMs: 300 }),
      ).rejects.toThrow(/docker run timed out/);
      const sweeps = calls().filter((c) => c[0] === 'ps' && c.some((a) => a.startsWith('label=kordn.contain.session=')));
      expect(sweeps).toHaveLength(2);
    });
  });

  it('rejects an image reference that could be read as a flag or is not a plain reference', async () => {
    for (const image of ['-v', '--privileged', '', 'a b', 'kordn\nsandbox', '../x', 'x;rm']) {
      await expect(runContain({ ...base, guardian: guardian(), platform: 'linux', image })).rejects.toThrow(/invalid image reference/);
    }
  });
});

describe('staleContainers', () => {
  const self = { boot: 'boot-1', pidns: '4026531836' };
  // Start time per pid. null: no such process. undefined: it exists but its start is unreadable.
  const starts = new Map<number, string | null | undefined>([
    [100, '5000'],
    [300, '7000'],
    [400, undefined],
  ]);
  const startOf = (pid: number) => (starts.has(pid) ? starts.get(pid) : null);

  it('reaps only when this host and PID namespace launched it and that launcher is gone', () => {
    const ps = [
      'a1 100 boot-1 4026531836 5000', // launcher alive: keep
      'b2 200 boot-1 4026531836 6000', // launcher dead: reap
      'c3 300 boot-1 4026531836 6500', // pid now belongs to another process: reap
      'd4 200 boot-2 4026531836 6000', // before a reboot, or another host: keep
      'e5 200 boot-1 4026532000 6000', // another PID namespace: keep
      'f6 200 boot-1 4026531836', // no start label: keep
      '07 notapid boot-1 4026531836 1', // garbled: keep
      '08 400 boot-1 4026531836 1', // alive, start unreadable (hidepid): keep
    ].join('\n');
    expect(staleContainers(ps, self, startOf)).toEqual(['b2', 'c3']);
  });
});

describe.runIf(process.platform === 'linux')('launcherIdentity', () => {
  it('reads the boot id, PID namespace inode and start time from /proc', () => {
    const id = launcherIdentity();
    expect(id.pid).toBe(process.pid);
    expect(id.boot).toBe(readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim());
    expect(readlinkSync('/proc/self/ns/pid')).toBe(`pid:[${id.pidns}]`);
    expect(id.start).toMatch(/^[0-9]+$/);
    expect(processStart(process.pid)).toBe(id.start);
    expect(processStart(2 ** 22 + 1)).toBeNull();
  });
});
