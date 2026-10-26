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
- **No secrets:** `scanImage` (`test/image-scan.ts`) reads every layer of `docker save`, so a file deleted in a later layer is still found, along with the image env, labels and `docker history`. It flags:
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
