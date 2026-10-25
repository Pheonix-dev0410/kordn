# Contain mode

In Contain mode the agent runs inside a locked-down container. Its only way out is the kordn
guardian socket. This is the setup the claims in [threat-model.md](threat-model.md) apply to.
It is Linux only. Design doc §9.

```
host                                         container (untrusted)
guardian ── /tmp/kordn-XXXX/guardian.sock ── /run/kordn.sock ── kordn --guardian ── agent (MCP over stdio)
admin UI, policy DB (never mounted)           no network, read-only, no capabilities
```

## The image

`sandbox/Dockerfile` is a multi-stage build:

- **build** (`node:24-slim`, pinned by digest): `npm ci`, then `npm run build`.
- **deps** (same base): `npm ci --omit=dev`.
- **runtime** (`gcr.io/distroless/nodejs24-debian13:nonroot`, pinned by digest): only `dist/`, production `node_modules`, `package.json` and `sandbox/agent.mjs`. Everything is root-owned. The image has no shell, no npm and no package manager, and runs as user `65532` (`nonroot`).

Build it from the repo root:

```sh
docker build -f sandbox/Dockerfile -t kordn-sandbox .
```

The build context is filtered by `sandbox/Dockerfile.dockerignore`. BuildKit uses the ignore
file next to the Dockerfile. It is an allowlist: only `package.json`, `package-lock.json`,
`tsconfig.json`, `src/` and `sandbox/agent.mjs` go in, and `.env*`, `.envrc`, `.git`,
`node_modules`, `*.sqlite*`, `.npmrc`, `*.pem` and `*.key` are excluded even inside those paths.

**BuildKit is required** (it is the default builder since Docker 23). The classic builder
(`DOCKER_BUILDKIT=0`) ignores the per-Dockerfile file. As a fallback, a root `.dockerignore`
denies the same secret, VCS, dependency and database entries, plus `.worktrees` and `dist`.
Under the classic builder the context is then bigger than the allowlist (docs and tests go in),
but no secrets do. BuildKit never reads the root file for this Dockerfile.

To update a base image, `docker pull` it and replace the `@sha256:` digest in the Dockerfile.

### The agent

v0.1 has no live model. The default command is `sandbox/agent.mjs`, a scripted MCP client. It:

1. starts `node /app/dist/index.js --guardian /run/kordn.sock` (kordn) over stdio;
2. lists the tools;
3. calls `af_get_balance`.

It prints one JSON line per step. To run a different agent, pass another script as the
command, for example `docker run … kordn-sandbox /app/sandbox/other-agent.mjs`. The entrypoint
is `/nodejs/bin/node`.

## Run flags

`kordn contain` launches the container with these flags (`hardenedRunFlags` in `src/sandbox.ts`):

| Flag | Why |
|---|---|
| `--network none` | No interface besides loopback, so there's no route to the bank, the admin UI or the internet |
| `--read-only` | The root filesystem can't be changed |
| `--ipc none` | Own IPC namespace with no `/dev/shm` mount, so there's no shared memory with anything else |
| `--tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m` | The only place the agent can write files (`/dev` and `/dev/pts` are root-owned, and there is no `/dev/shm`). It's in memory and disappears with the container |
| `--cap-drop ALL` | No Linux capabilities, including the bounding set |
| `--security-opt no-new-privileges` | setuid binaries and file capabilities can't raise privileges |
| `--pids-limit 64 --memory 512m --memory-swap 512m --cpus 1` | Resource limits. No swap on top of the memory limit |
| `--user <uid>:<gid>` | Non-root (see below) |
| `--mount type=bind,src=<socket>,dst=/run/kordn.sock,readonly` | The guardian socket is the only host path in the container |

Nothing else is passed: no `-e` variables, no other mounts or devices, and no `--privileged`
or `--pid/--ipc/--uts host`. The launcher refuses socket paths containing `,` or `"`, because
those could add `--mount` options.

## Socket access

The guardian socket lives in a fresh private directory (`mkdtemp`, mode `0700`) owned by the
user running kordn. No other host user can reach it, whatever the socket's own mode.

- **Rootful Docker:** container uids are host uids. The container runs as the launching user (`--user $(id -u):$(id -g)`) and the socket is `0600`. kordn refuses to run the sandbox as root (uid or gid 0).
- **Rootless Docker:** container root *is* the launching user, and every other container uid maps to a subordinate id that can't own host files. The container runs as the image user `65532:65532` and the socket is `0666`. It stays private because the `0700` directory is only traversable by the launching user. The bind mount is resolved by the rootless daemon, which runs as that user.

  **The rootless path is unverified:** the development host runs rootful Docker. It is implemented and unit-tested, but it hasn't been run end-to-end against a rootless daemon.

## Verifying the image

These tests need Docker and are skipped by plain `npm test`:

```sh
KORDN_DOCKER_TESTS=1 npx vitest run test/sandbox-image.test.ts
```

They build the image (tagged `kordn-test-*`, removed afterwards) and check:

- **Contents:** `/app` holds only `dist`, `node_modules` (only `zod`), `package.json` and `sandbox/agent.mjs`. There is no shell or npm, and the user is `65532`.
- **No secrets:** `scanImage` (`src/image-scan.ts`) reads every layer of `docker save`, so a file deleted in a later layer is still found, along with the image env, labels and `docker history`. It flags:
  - env, credential, key, VCS and database files by name;
  - private keys and common API token formats by content;
  - secret-named `NAME=value` entries in env, labels and history.

  A planted-secret image proves it catches them.
- **Build context:** a context full of junk (`.env`, `.git`, `node_modules`, `*.sqlite`, `dist`, `docs`, `test`, worktrees), laid out like the repo, passes only the allowlisted files under BuildKit even with the root `.dockerignore` present. Under the classic builder the root file keeps every planted secret out.
- **Inside the hardened container**, against `serveGuardianSocket` and the fake guardian on the host:
  - a guardian call through `/run/kordn.sock` works;
  - only `lo` exists and there are no routes;
  - connects to public IPv4/IPv6, the Docker gateway, 169.254.169.254 and the host's LAN addresses all fail with `ENETUNREACH`;
  - a listener on the host's `127.0.0.1` is never reached;
  - the daemon socket (the default paths, the one named by `DOCKER_HOST` or the docker context, and the rootless `$XDG_RUNTIME_DIR/docker.sock`), the host home directory and `$SSH_AUTH_SOCK` are absent; there is no `/dev/shm`, and the env has no `SSH_AUTH_SOCK`;
  - the only non-Docker mount is the socket;
  - writes give `EROFS`;
  - all capability sets are empty, with `NoNewPrivs: 1` and `Seccomp: 2`;
  - the pids and memory limits are in force.
- **Agent end-to-end:** the agent lists tools and makes a read call through kordn. This test is skipped until the MCP server (`dist/index.js`, #9) is in the image.

The scanner is a heuristic. It catches obvious mistakes but can't prove that no secrets are present.

### What the probe can and can't prove

The probe runs on the image's own `node` binary (`docker exec … /nodejs/bin/node -`). It is
evidence from inside the boundary, not an authority: a tampered image could ship a `node` that
prints a forged result. `docker inspect` facts come from the daemon and the loopback canary counts
connections on the host side, and neither depends on the probe. Most checks need both the
daemon's configuration and the probe to agree, so a forged probe can't pass them on its own.
The exceptions rest on the probe alone: reaching the guardian socket, and the admin UI port and
guardian DB path being out of reach. For those, the host-side canary is the only independent
signal, and it only covers host loopback. Build the image yourself from this repo, and run it by
its local image ID (`sha256:…`, which `kordn contain` resolves from the tag before starting),
so a re-tagged image can't be swapped in. The ID comes from this daemon's local image store; it
is not a registry digest, which a locally built image doesn't have.

## `kordn contain`: launch and verify

`runContain(options)` in `src/sandbox.ts` is what the `kordn contain` command runs (the CLI
wiring lives with the MCP server, #9). It:

1. **Refuses on anything but Linux**, macOS included, with "Contain mode is not supported on <platform>". Use Guard mode there. It also refuses an image reference that isn't a plain name or ID (for example one starting with `-`).
2. **Resolves the image to its ID** (`sha256:…`) and runs exactly that image, so a re-tag can't swap it in between.
3. **Starts the guardian on the host.** It makes a private `0700` directory and calls `serveGuardianSocket(guardian, agentId, socket)`. The agent's identity is bound to that socket, never taken from the agent.
4. **Launches the container idle** with the hardened flags above, labelled `kordn.contain=<launcher pid>`. PID 1 is `node -e 'setInterval(…)'`, so the agent hasn't started. The probe that runs next uses the image's own `node` (see [What the probe can and can't prove](#what-the-probe-can-and-cant-prove)). Every later call uses the container ID that `docker run` printed, not the name.
5. **Runs the isolation checks** below, using `docker inspect`/`docker info` for configuration and a probe piped into `docker exec … node -` for runtime facts. A host-side canary listener on `127.0.0.1` stands in for the admin UI.
6. **Prints the coverage report** through `onReport` (by default to stderr), then **runs the agent** with `docker exec` in that same container. The default agent is the image's command; `agentCommand` replaces it.
7. **Cleans up** in all cases. It removes the container (with a warning if that fails), drops any open guardian connections so it can't hang, closes the socket and the canary, and deletes the directory. It refuses to start if the container name is already taken, so it never removes a container it didn't create.

**Signals.** Cleanup runs in a `finally`, which a signal skips. The `kordn contain` CLI must
install `SIGINT`/`SIGTERM` handlers that make `runContain` finish (and await it) before exiting.
For a launcher that was killed outright (`SIGKILL`), `reapStaleContainers()` removes every
container labelled `kordn.contain` whose launcher pid no longer exists. Run it before a new
session.

The mode is **Contain only if every check passes**. Any failure means **Guard**: kordn still
checks every tool call, but the agent isn't contained. The report lists each failing check and
the reason. In Guard mode the agent still runs, labelled Guard. Pass `requireContain: true` to
refuse to run it instead.

```ts
const { report, agent } = await runContain({
  guardian,                 // the Guardian (the fake for now, the real one after #6)
  agentId: 'sandbox-demo-01',
  image: 'kordn-sandbox',
  adminPort: 3333,          // optional: the admin UI port that must be unreachable
  dbPath: '/home/me/.kordn/kordn.sqlite', // optional: must not be visible inside
  requireContain: false,
});
```

On a rootful daemon the report looks like this:

```
kordn contain: GUARD mode (linux, image sha256:…)
  FAIL  rootless                 Docker daemon is rootful (no name=rootless in docker info): container root is host root
  ok    network                  no network: only lo, no routes, 7 outside addresses unreachable
  ok    readOnlyRootfs           root filesystem is read-only (writes fail with EROFS); /tmp is a nosuid,nodev,noexec tmpfs
  …
  FAIL  namespaces               in the host's initial user namespace
  …
2 isolation checks failed. Running in Guard mode: kordn still checks every call, but the agent is not contained.
```

### The checks

Each check passes only if the container's **configuration** (`docker inspect` / `docker info`)
and the **runtime evidence** from inside agree. If the probe produces no output or anything it
can't parse, every runtime-backed check fails. So does a target the probe didn't report on.
Anything not explicitly allowed fails: the checks deny by default.

| Check | Configuration | Runtime (inside the container) |
|---|---|---|
| `rootless` | `docker info` security options include `name=rootless` | n/a |
| `network` | network mode `none`, no other networks attached | only `lo`; no IPv4 routes; IPv6 routes only on `lo`; connects to public IPv4/IPv6, the Docker gateway, 169.254.169.254 and every host address fail with `ENETUNREACH`/`EHOSTUNREACH` |
| `readOnlyRootfs` | `--read-only`; the only tmpfs is `/tmp`, with options exactly `rw,nosuid,nodev,noexec,size=64m` (Docker applies later options, so `…,noexec,exec` must not pass) | `/` mounted `ro`; `/tmp` mounted `nosuid,nodev,noexec`; writes in `/`, `/etc`, `/usr`, `/var`, `/app`, `/run` fail with **`EROFS`**. `EACCES` doesn't count: it's also what a *writable* root gives a non-root user |
| `onlyGuardianSocket` | exactly one mount: the socket, read-only bind, from the expected host path; no devices, device cgroup rules or device requests (`--gpus`) | no Docker daemon socket (the default paths, the one named by `DOCKER_HOST` or the docker context, and the rootless `$XDG_RUNTIME_DIR/docker.sock`), host home dir or `$SSH_AUTH_SOCK`; every mount point is one Docker always creates (checked by filesystem type and source), or the socket |
| `noHostEnv` | no variables beyond the image's own | no variable names beyond the image's, `HOSTNAME` and `HOME` (values are never read) |
| `nonRoot` | numeric non-zero uid (and gid) | uid ≠ 0, gid ≠ 0, not in group 0 |
| `capabilities` | `--cap-drop ALL`, nothing added, not privileged | all five capability sets are zero, including the bounding set |
| `noNewPrivileges` | `no-new-privileges` set | `NoNewPrivs: 1` |
| `seccomp` | the daemon uses Docker's builtin profile (`name=seccomp,profile=builtin`); no per-container `seccomp=` option; not privileged. A custom profile, even a stricter one, means Guard | `Seccomp: 2` (filter active) |
| `hardening` | security options are exactly `no-new-privileges` (so `systempaths=unconfined`, `apparmor=unconfined`, `label=disable` and profiles all fail; Docker adds `label=disable` itself for `--pid host`/`--ipc host`); Docker's default masked and read-only `/proc` and `/sys` paths present; runtime `runc` or `crun` | `/proc/sys` mounted read-only and `/proc/kcore` masked |
| `namespaces` | pid, uts, user and cgroup namespaces not `host` or another container's; IPC mode `none` | PID 1 is the sandbox's own idle process; no `/dev/shm`; each of its cgroup, ipc, mnt, net, pid, user and uts namespaces differs from the launcher's and from the kernel's initial one (fixed inode numbers, so this holds even if the launcher runs in its own namespaces) |
| `resourceLimits` | pids ≤ 64, memory ≤ 512m, swap = memory (no extra), cpus ≤ 1 | `pids.max` and `memory.max` set within those limits |
| `hostServicesUnreachable` | n/a | the canary and the admin UI port on `127.0.0.1` and `::1` can't be reached, and the host-side canary saw no connections; the guardian DB path, if given, doesn't exist |
| `guardianSocket` | n/a | `/run/kordn.sock` accepts a connection (no request is sent, so this uses no quota) |

The check logic is pure (`evaluateIsolation` in `src/sandbox-checks.ts`) and unit-tested
against a fixture captured from a real hardened container, mutated into each unsafe setting.
The settings the flags set and the checks require (socket path, `/tmp` options, security
options, allowed runtimes) live in one place, `src/sandbox-contract.ts`.

### What real Contain needs

On a rootful Docker daemon `kordn contain` reports **Guard**, and that's correct. `rootless`
fails, and so does `namespaces`, because the container shares the host's initial user
namespace: if anything breaks out of the container, it is root on the host. For Contain:

1. Run Docker in [rootless mode](https://docs.docker.com/engine/security/rootless/) as the user who runs kordn: `dockerd-rootless-setuptool.sh install`, then `export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock`. Use cgroup v2 with delegation, otherwise the pids and memory limits can't be enforced and `resourceLimits` fails.
2. Keep Docker's builtin seccomp profile (no `seccomp-profile` in `daemon.json`) and the `runc` or `crun` runtime.
3. Build the image under that daemon (`docker build -f sandbox/Dockerfile -t kordn-sandbox .`).
4. Run `kordn contain`. Every check must say `ok`.

Under rootless Docker the container runs as `65532:65532` and the socket is `0666` inside the
private `0700` directory (see [Socket access](#socket-access)). **This path hasn't been verified
against a real rootless daemon yet.** Rootless runtimes can also differ in their default mounts
(for example how `/sys` is provided). If `onlyGuardianSocket` or `hardening` reports an
unexpected or missing mount there, that's the check failing closed and needs a look. It doesn't
mean the sandbox is unsafe.

### Tests

```sh
npm test                                                     # pure checks, probe, runner (no Docker)
KORDN_DOCKER_TESTS=1 npx vitest run test/contain-docker.test.ts
```

The Docker test runs `runContain` end to end and checks that `reapStaleContainers` removes only
containers whose launcher is gone. It also launches each unsafe variant for real and asserts
exactly which checks fail:

- bridge network
- host network (the host canary is reached)
- writable rootfs (non-root writes get `EACCES`)
- `docker.sock` mounted
- a home dir mounted
- root user (it also can't open the socket: no `CAP_DAC_OVERRIDE`)
- no cap-drop
- no no-new-privileges
- `seccomp=unconfined`
- a permissive allow-all seccomp profile
- `systempaths=unconfined`
- `apparmor=unconfined`
- `label=disable`
- a device cgroup rule
- a `/tmp` tmpfs re-enabling `exec,suid,dev`
- a runtime outside the allowlist
- `--pid host`
- `--ipc host`
- `--ipc private` (with `/dev/shm`)
- `--uts host`
- no resource limits
- `-e` variables
- a forwarded SSH agent
- a uid that can't open the `0600` socket

A daemon-wide custom seccomp profile would mean reconfiguring the daemon, and other OCI runtimes
(gVisor's `runsc`, Kata) aren't installed here, so those are covered by unit fixtures only.
