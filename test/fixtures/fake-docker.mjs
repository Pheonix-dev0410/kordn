#!/usr/bin/env node
// Fake docker CLI for runner unit tests: logs argv, answers info/image inspect, and says
// the container name is already taken.
import { appendFileSync } from 'node:fs';
const args = process.argv.slice(2);
appendFileSync(process.env.FAKE_DOCKER_LOG, `${JSON.stringify(args)}\n`);
if (args[0] === 'info') process.stdout.write('["name=seccomp,profile=builtin"]');
else if (args[0] === 'image') process.stdout.write('{"Entrypoint":["/nodejs/bin/node"],"Cmd":["/app/sandbox/agent.mjs"],"Env":[]}');
else if (args[0] === 'inspect') process.stdout.write('[{"Name":"/taken"}]');
else process.exit(1);
