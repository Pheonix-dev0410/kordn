#!/usr/bin/env node
// Fake docker CLI for runner unit tests. Logs argv (one JSON array per line) to $FAKE_DOCKER_LOG.
//   FAKE_DOCKER_MODE=taken  every container name is already in use
//   FAKE_DOCKER_MODE=flow   the name is free; `run` holds a guardian connection open (like an
//                           agent that never hangs up) and prints a container ID; the probe
//                           prints garbage (so the report is Guard); the agent prints "agent ran"
//   FAKE_DOCKER_RM_FAIL=1   `rm` fails
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
    out(args.includes('--input-type=module') ? 'garbage' : 'agent ran\n');
    break;
  case 'rm':
    if (process.env.FAKE_DOCKER_RM_FAIL) {
      process.stderr.write('Error response from daemon: removal failed');
      process.exit(1);
    }
    break;
  default:
    process.exit(1);
}
