# Supported runtime (v0.1)

| | Supported | Notes |
|---|---|---|
| Host OS | Ubuntu 24.04 LTS | Reference. Other Linux may work but cannot claim Contain until `sandbox:verify` passes there |
| macOS / Windows | Development only | Unit tests run; there is no Contain claim (Docker Desktop runs a VM, so the isolation checks don't apply) |
| Node.js | 24 LTS | Pinned via `.nvmrc` |
| Package manager | pnpm 10.34.8 | Pinned via `packageManager`; use `corepack enable` |
| Container runtime | Docker Engine, rootless mode | No Docker socket inside the container, ever |
| MCP | Protocol 2026-07-28, official TypeScript SDK v2 (`@modelcontextprotocol/server` / `client`) | Exact versions pinned in the lockfile |
| Agent | `apps/agent-runner` (our scripted runner) | Arbitrary hosted agents are **not** supported |

## Explicit bypasses (outside the guarantee)

- Running the agent outside the launcher-created container.
- Giving the agent any additional tool, mount, socket or network route.
- Root on the host, or a modified guardian binary.
- Observe and Guard modes. Only Contain is sandbox-backed.
