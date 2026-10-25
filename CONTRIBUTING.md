# Contributing

## Setup

```sh
corepack enable
pnpm install --frozen-lockfile
pnpm lint && pnpm typecheck && pnpm test:unit
```

## Branching (v0.1 team workflow)

- `main`: integrated, always green.
- `track/core`: trusted core (policy, db, guardian, adapter-mock). Owner: @immortal1405.
- `track/boundary`: sandbox boundary and UX (mcp-shim, launcher, agent-runner, admin-ui, adversarial driver). Owner: @rzzdr.

Per issue: branch off your track (`track/core` → `core/<issue#>-short-name`), open a PR **into your track branch**, link the issue (`Closes #N`), and keep CI green. When a track is complete, the integrator merges it into `main` and runs the full end-to-end gates.

### Changing shared contracts

`packages/contracts` is the seam between the tracks. Do not change it on a track branch. Open a small PR against `main` that touches only `packages/contracts` (plus its tests), get a review from the other track owner, then merge `main` into your track.

## Rules (design doc §11.4)

- Never add a side-effecting tool without a reviewed typed schema, an explicit policy mapping, an audit event definition, and deny/bypass tests.
- Trust-boundary changes (guardian, sandbox/launcher, policy schema, admin auth, persistence) need **two** approvals.
- Every object schema is strict (unknown keys rejected). Default is deny.
- No LLM in any authorization path. No "fallback" to an unguarded path when something is down.
- Tests must be deterministic: seeded data and `FakeClock` from `@kordn/contracts/testing`, never wall-clock sleeps or a live model.
- Never commit real credentials, real account data, or `.sqlite` files.
