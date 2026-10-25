# Security policy

Kordn v0.1 is an **experimental research prototype** that protects a mock bank with fake money. It makes no promise of banking-grade protection and must not be used to guard real funds.

## Reporting a vulnerability

Please report suspected bypasses privately through GitHub's **Security → Report a vulnerability** on this repository. Do not open a public issue. Include the commit, runtime (see `docs/supported-runtime.md`), and a reproduction script.

A bypass is anything that violates an invariant in `docs/threat-model.md` within the declared supported setup.

## Supported versions

Only the latest `main` and the latest `v0.1.x-alpha` tag.
