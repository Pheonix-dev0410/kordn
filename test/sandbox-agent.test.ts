import { execFile } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

// sandbox/agent.mjs against a fake stdio MCP server. Interop with the real kordn server
// (#9) is checked by the Docker test once dist/index.js exists.

const agent = join(import.meta.dirname, '../sandbox/agent.mjs');
const fakeServer = join(import.meta.dirname, 'fixtures/fake-mcp-server.mjs');

const dirs: string[] = [];
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function runAgent(variant: string, extra: string[] = []) {
  const dir = mkdtempSync(join(tmpdir(), 'kordn-test-'));
  dirs.push(dir);
  const log = join(dir, 'server.log');
  return new Promise<{ code: number | null; lines: unknown[]; received: Record<string, unknown>[] }>((resolve) => {
    execFile(
      process.execPath,
      [agent, ...extra, '--', process.execPath, fakeServer, log, variant],
      { timeout: 10_000 },
      (err, stdout) => {
        resolve({
          code: err ? (typeof err.code === 'number' ? err.code : null) : 0,
          lines: stdout.split('\n').filter(Boolean).map((l) => JSON.parse(l)),
          received: readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)),
        });
      },
    );
  });
}

describe('sandbox agent', () => {
  it('connects, lists tools and makes one read call', async () => {
    const { code, lines, received } = await runAgent('stateful');
    expect(code).toBe(0);
    expect(received.map((m) => m.method)).toEqual(['initialize', 'notifications/initialized', 'tools/list', 'tools/call']);
    expect(received[3]).toMatchObject({
      params: { name: 'af_get_balance', arguments: { resourceId: 'mock-bank:checking-01' } },
    });
    expect(lines).toEqual([
      { step: 'tools/list', tools: ['af_get_balance', 'af_list_transactions'] },
      { step: 'tools/call', tool: 'af_get_balance', isError: false, result: { currency: 'USD', balanceMinor: 1 } },
    ]);
  });

  it('works with a stateless server that has no initialize', async () => {
    const { code, received } = await runAgent('stateless');
    expect(code).toBe(0);
    expect(received.map((m) => m.method)).toEqual(['initialize', 'tools/list', 'tools/call']);
  });

  it('takes the resource id from the command line', async () => {
    const { received } = await runAgent('stateful', ['--resource', 'mock-bank:savings-02']);
    expect(received[3]).toMatchObject({ params: { arguments: { resourceId: 'mock-bank:savings-02' } } });
  });

  it('ignores junk lines, notifications and server requests that reuse a pending id', async () => {
    const { code, lines } = await runAgent('noisy');
    expect(code).toBe(0);
    expect(lines).toEqual([
      { step: 'tools/list', tools: ['af_get_balance', 'af_list_transactions'] },
      { step: 'tools/call', tool: 'af_get_balance', isError: false, result: { currency: 'USD', balanceMinor: 1 } },
    ]);
  });

  it('exits non-zero when the read call is denied', async () => {
    const { code, lines } = await runAgent('deny');
    expect(code).toBe(1);
    expect(lines.at(-1)).toMatchObject({ step: 'tools/call', isError: true });
  });

  it('exits non-zero when the server cannot start', async () => {
    const result = await new Promise<number | null>((resolve) =>
      execFile(process.execPath, [agent, '--', '/nonexistent/kordn'], { timeout: 10_000 }, (err) =>
        resolve(err && typeof err.code === 'number' ? err.code : 0),
      ),
    );
    expect(result).not.toBe(0);
  });
});
