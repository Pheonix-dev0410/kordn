import { execFileSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { expect, it } from 'vitest';

// npm run demo, minus the build (test/build.ts builds once, before all test files): each
// scene prints what kordn did and what the bank sent.

const root = resolve(import.meta.dirname, '..');

it('runs every demo scene and shows the expected outcomes', () => {
  const output = execFileSync(process.execPath, ['--disable-warning=ExperimentalWarning', join(root, 'dist', 'demo.js')], {
    encoding: 'utf8',
    // The whole environment, so docker finds its daemon.
    env: process.env,
  });
  expect(output).toContain('transfer $500.00 to attacker -> denied, UNAPPROVED_PAYEE');
  expect(output).toContain('kordn: 3 sent, 7 denied (FREQUENCY_LIMIT)');
  expect(output).toContain('-> denied, SESSION_REVOKED');
  expect(output).toMatch(/a fourth -> denied, FREQUENCY_LIMIT/);
  expect(output).toContain('mock bank: 3 transfers, $150.00: the retry was not sent again');
  if (process.env.KORDN_DOCKER_TESTS === '1' && process.platform === 'linux') {
    // CI builds kordn-sandbox first. Every escape attempt has to fail.
    expect(output).toMatch(/isolation checks: \d+\/\d+ passed/);
    expect(output).toMatch(/agent \| internet \(1\.1\.1\.1:443\): /);
    expect(output).not.toMatch(/CONNECTED|: READ$/m);
  }
}, 120_000);
