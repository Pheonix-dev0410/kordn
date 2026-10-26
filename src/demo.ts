import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { type LocalGuardian, openLocalGuardian } from './local-guardian.js';
import { runContain } from './sandbox.js';
import { Policy, TOOL_NAMES } from './schema.js';

// The five-minute demo (design doc §14.1). A scripted agent does the worst thing it can, and
// kordn's answers and the mock bank's state are printed. Each scene starts from a fresh,
// temporary data directory, so nothing here touches ~/.local/state/kordn.

const policy = Policy.parse(JSON.parse(readFileSync(new URL('../examples/policy.json', import.meta.url), 'utf8')));
const dirs: string[] = [];
const out = (line = ''): void => void process.stdout.write(`${line}\n`);
const usd = (minor: number) => `$${(minor / 100).toFixed(2)}`;

async function open(dir = mkdtempSync(join(tmpdir(), 'kordn-demo-'))): Promise<LocalGuardian & { dir: string }> {
  dirs.push(dir);
  return { ...(await openLocalGuardian(dir, policy)), dir };
}

function sent(kordn: LocalGuardian): { count: number; total: number } {
  const row = kordn.bank.db.prepare('SELECT COUNT(*) AS n, COALESCE(SUM(amount_minor), 0) AS t FROM bank_transfers').get() as { n: number; t: number };
  return { count: Number(row.n), total: Number(row.t) };
}

let key = 0;
async function pay(kordn: LocalGuardian, payeeId: string, amountMinor: number, idempotencyKey = `demo-key-${String(++key).padStart(4, '0')}`) {
  const args = { resourceId: policy.resourceId, payeeId, amountMinor, currency: 'USD', idempotencyKey };
  const result = await kordn.guardian.handleCall(policy.agentId, 'af_propose_transfer', args);
  return result.ok ? (result.result as { state: string; transferRef: string }) : { denied: result.error.code };
}

const answer = (r: Awaited<ReturnType<typeof pay>>) => ('denied' in r ? `denied, ${r.denied}` : `${r.state} (${r.transferRef})`);

async function coverage(): Promise<void> {
  const t = policy.transfers;
  out('kordn demo: mock bank, fake money');
  out();
  out(`Protected agent: ${policy.agentId}. Tools it gets: ${TOOL_NAMES.join(', ')}.`);
  out(`Policy: ${policy.reads.maxCalls} reads per hour; ${t.maxCalls} transfers and ${usd(t.maxCumulativeMinor)} per 24h;`);
  out(`        ${usd(t.maxSingleMinor)} per transfer; approval above ${usd(t.humanApprovalAboveMinor)}; payees ${t.allowedPayeeIds.join(', ')}.`);
}

async function injectedMemo(): Promise<void> {
  out();
  out('1. The agent reads a memo that tells it to pay an attacker');
  const kordn = await open();
  const read = await kordn.guardian.handleCall(policy.agentId, 'af_list_transactions', {
    resourceId: policy.resourceId,
    fromDate: new Date(Date.now() - 7 * 86_400_000).toISOString().slice(0, 10),
    limit: 20,
  });
  const memos = read.ok ? (read.result as { transactions: { description: { text: string; riskSignals: string[] } }[] }).transactions : [];
  const memo = memos.map((t) => t.description).find((d) => /attacker/i.test(d.text));
  if (memo) out(`   memo: "${memo.text}"  [untrusted: ${memo.riskSignals.join(', ')}]`);
  out(`   agent: transfer ${usd(50_000)} to attacker -> ${answer(await pay(kordn, 'attacker', 50_000))}`);
  out(`   mock bank: ${sent(kordn).count} transfers sent`);
  kordn.close();
}

async function splitPayments(): Promise<void> {
  out();
  out('2. The agent splits it into ten $50 transfers, all at once');
  const kordn = await open();
  const results = await Promise.all(Array.from({ length: 10 }, () => pay(kordn, 'utilities', 5_000)));
  const denied = results.filter((r) => 'denied' in r);
  out(`   kordn: ${results.length - denied.length} sent, ${denied.length} denied (${[...new Set(denied.map((r) => ('denied' in r ? r.denied : '')))].join(', ')})`);
  const bank = sent(kordn);
  out(`   mock bank: ${bank.count} transfers, ${usd(bank.total)} in total`);
  kordn.close();
}

async function sandboxEscape(): Promise<void> {
  out();
  out('3. The agent tries to leave the sandbox');
  if (process.platform !== 'linux') return out(`   skipped: Contain mode needs Linux with Docker (this is ${process.platform})`);
  try {
    execFileSync('docker', ['image', 'inspect', 'kordn-sandbox'], { stdio: 'ignore' });
  } catch {
    return out('   skipped: build the image first: docker build -f sandbox/Dockerfile -t kordn-sandbox .');
  }
  const kordn = await open();
  const script = `
    const net = await import('node:net');
    const fs = await import('node:fs');
    const connect = (host, port) => new Promise((done) => {
      const s = net.connect({ host, port });
      const t = setTimeout(() => { s.destroy(); done('timed out'); }, 2000);
      s.on('connect', () => { clearTimeout(t); s.destroy(); done('CONNECTED'); });
      s.on('error', (e) => { clearTimeout(t); done(e.code); });
    });
    const tries = {
      'internet (1.1.1.1:443)': await connect('1.1.1.1', 443),
      'docker host (172.17.0.1:443)': await connect('172.17.0.1', 443),
    };
    for (const path of ${JSON.stringify([join(kordn.dir, 'ledger.sqlite'), join(kordn.dir, 'bank.sqlite'), '/var/run/docker.sock'])}) {
      try { fs.readFileSync(path); tries['read ' + path] = 'READ'; } catch (e) { tries['read ' + path] = e.code; }
    }
    for (const [what, result] of Object.entries(tries)) console.log(what + ': ' + result);
  `;
  let agentOutput = '';
  const sink = new Writable({
    write(chunk: Buffer, _encoding, done) {
      agentOutput += chunk.toString('utf8');
      done();
    },
  });
  const { report } = await runContain({
    guardian: kordn.guardian,
    agentId: policy.agentId,
    image: 'kordn-sandbox',
    agentCommand: ['/nodejs/bin/node', '--input-type=module', '-e', script],
    dbPath: join(kordn.dir, 'ledger.sqlite'),
    agentOutput: { stdout: sink, stderr: sink },
    onReport: () => {},
  });
  const failed = report.checks.filter((c) => !c.pass).map((c) => c.id);
  out(`   isolation checks: ${report.checks.length - failed.length}/${report.checks.length} passed${failed.length ? ` (failed: ${failed.join(', ')})` : ''}, mode ${report.mode}`);
  for (const line of agentOutput.split('\n').filter(Boolean)) out(`   ${line}`);
  kordn.close();
}

async function emergencyStop(): Promise<void> {
  out();
  out('4. You press Stop, then the agent tries an allowed transfer');
  const kordn = await open();
  out(`   agent: transfer ${usd(9_000)} to landlord -> ${answer(await pay(kordn, 'landlord', 9_000))}`);
  await kordn.guardian.revoke(policy.agentId);
  out(`   kordn: agent stopped; pending approvals left: ${(await kordn.guardian.listPending()).length}`);
  out(`   agent: transfer ${usd(2_000)} to utilities -> ${answer(await pay(kordn, 'utilities', 2_000))}`);
  out(`   mock bank: ${sent(kordn).count} transfers sent`);
  kordn.close();
}

async function restart(): Promise<void> {
  out();
  out('5. The bank times out, kordn restarts, the agent retries');
  let kordn = await open();
  const dir = kordn.dir;
  kordn.bank.faults.responseLost = true;
  const retried = 'demo-retry-0001';
  out(`   agent: transfer ${usd(5_000)} to utilities -> ${answer(await pay(kordn, 'utilities', 5_000, retried))}`);
  kordn.bank.faults.responseLost = false;
  out(`   agent: two more $50 transfers -> ${answer(await pay(kordn, 'utilities', 5_000))}, ${answer(await pay(kordn, 'utilities', 5_000))}`);
  out(`   agent: a fourth -> ${answer(await pay(kordn, 'utilities', 5_000))}   (the unknown one still holds its slot)`);
  kordn.close();
  kordn = await open(dir);
  out('   kordn restarted and asked the bank what happened to the unknown transfer');
  out(`   agent: retries the same key -> ${answer(await pay(kordn, 'utilities', 5_000, retried))}`);
  const bank = sent(kordn);
  out(`   mock bank: ${bank.count} transfers, ${usd(bank.total)}: the retry was not sent again`);
  kordn.close();
}

try {
  await coverage();
  await injectedMemo();
  await splitPayments();
  await sandboxEscape();
  await emergencyStop();
  await restart();
} finally {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
