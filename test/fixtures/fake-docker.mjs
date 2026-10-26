#!/usr/bin/env node
// Fake docker CLI for runner unit tests. Logs argv (one JSON array per line) to $FAKE_DOCKER_LOG.
//   FAKE_DOCKER_MODE=taken  every container name is already in use
//   FAKE_DOCKER_MODE=flow   the name is free; `run` holds a guardian connection open (like an
//                           agent that never hangs up) and prints a container ID; the probe
//                           prints garbage (so the report is Guard); the agent prints "agent ran"
//   FAKE_DOCKER_MODE=slowrun like flow, but `run` hangs past the launcher's timeout
//   FAKE_DOCKER_MODE=hang   like flow, but the agent prints "agent started" and never exits
//   FAKE_DOCKER_AGENT_EXIT=n the agent exits with status n
//   FAKE_DOCKER_AGENT_BYTES=n after "agent ran", the agent writes n more bytes of "x" to stdout
//   FAKE_DOCKER_AGENT_SIGNAL=SIG  the agent's docker exec is killed by this signal
//   FAKE_DOCKER_AGENT_CHUNKS=[["out"|"err", base64], ...] the agent writes exactly these, 50 ms apart
//   FAKE_DOCKER_RM_FAIL=1   `rm` fails
//   FAKE_DOCKER_RM_SLOW=1   `rm` takes 5 seconds
//   FAKE_DOCKER_PS_SLOW=1   `ps` (the reaper's listing) takes 10 seconds
//   FAKE_DOCKER_PROBE_DELAY_MS=n  the probe answers after n ms
// The probe script (the probe's stdin) is appended to $FAKE_DOCKER_LOG.probe.
import { spawn } from 'node:child_process';
import { appendFileSync } from 'node:fs';

const args = process.argv.slice(2);
const mode = process.env.FAKE_DOCKER_MODE ?? 'taken';
appendFileSync(process.env.FAKE_DOCKER_LOG, `${JSON.stringify(args)}\n`);
const CONTAINER_ID = 'c'.repeat(64);
const out = (s) => process.stdout.write(s);

switch (args[0]) {
  case 'info':
    out('{"SecurityOptions":["name=seccomp,profile=builtin"],"Runtimes":{"runc":{"path":"runc"}}}');
    break;
  case 'image':
    out(JSON.stringify({ Id: `sha256:${'a'.repeat(64)}`, Config: { Entrypoint: ['/nodejs/bin/node'], Cmd: ['/app/sandbox/agent.mjs'], Env: [] } }));
    break;
  case 'context':
    out('unix:///var/run/docker.sock\n');
    break;
  case 'inspect':
    if (mode === 'taken') out('[{"Name":"/taken"}]');
    else if (args.at(-1) === CONTAINER_ID) out('[{}]');
    else process.exit(1);
    break;
  case 'run': {
    if (mode === 'slowrun') {
      setTimeout(() => {}, 10_000); // never answers within the launcher's timeout
      break;
    }
    const mount = args[args.indexOf('--mount') + 1] ?? '';
    const socket = /src=([^,]+)/.exec(mount)?.[1];
    const holder = spawn(
      process.execPath,
      ['-e', `const s = require('net').connect(${JSON.stringify(socket)}, () => process.stdout.write('up')); s.on('close', () => process.exit(0)); s.on('error', () => process.exit(0)); setTimeout(() => {}, 60000);`],
      { detached: true, stdio: ['ignore', 'pipe', 'ignore'] },
    );
    holder.stdout.once('data', () => {
      holder.stdout.destroy();
      holder.unref();
      out(`${CONTAINER_ID}\n`);
    });
    break;
  }
  case 'exec':
    if (args.includes('--input-type=module')) {
      let script = '';
      process.stdin.on('data', (d) => (script += d));
      process.stdin.on('end', () => {
        appendFileSync(`${process.env.FAKE_DOCKER_LOG}.probe`, script);
        setTimeout(() => out('garbage'), Number(process.env.FAKE_DOCKER_PROBE_DELAY_MS ?? 0));
      });
      break;
    }
    if (mode === 'hang') {
      out('agent started\n');
      setTimeout(() => {}, 60_000);
      break;
    }
    if (process.env.FAKE_DOCKER_AGENT_SIGNAL) process.kill(process.pid, process.env.FAKE_DOCKER_AGENT_SIGNAL);
    if (process.env.FAKE_DOCKER_AGENT_CHUNKS) {
      const chunks = JSON.parse(process.env.FAKE_DOCKER_AGENT_CHUNKS);
      chunks.forEach(([stream, data], i) =>
        setTimeout(() => (stream === 'out' ? process.stdout : process.stderr).write(Buffer.from(data, 'base64')), 50 * i),
      );
      break;
    }
    out('agent ran\n');
    if (process.env.FAKE_DOCKER_AGENT_BYTES) out('x'.repeat(Number(process.env.FAKE_DOCKER_AGENT_BYTES)));
    process.exitCode = Number(process.env.FAKE_DOCKER_AGENT_EXIT ?? 0);
    break;
  case 'ps':
    if (process.env.FAKE_DOCKER_PS_SLOW) setTimeout(() => {}, 10_000);
    break;
  case 'rm':
    if (process.env.FAKE_DOCKER_RM_SLOW) {
      setTimeout(() => {}, 5000);
      break;
    }
    if (process.env.FAKE_DOCKER_RM_FAIL) {
      process.stderr.write('Error response from daemon: removal failed');
      process.exit(1);
    }
    break;
  default:
    process.exit(1);
}
