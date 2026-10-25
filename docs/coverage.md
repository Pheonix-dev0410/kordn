# Coverage matrix

| Mode | Meaning | Guarantee |
|---|---|---|
| Observe | Calls are logged; nothing is enforced | None |
| Guard | Guardian enforces policy on calls it sees; the agent may still have other routes | Only for calls that go through the shim |
| **Contain** | Guard + launcher-verified sandbox (no network, only the broker socket, no secrets) | Guarded mock-bank actions cannot execute outside policy |

| Surface | v0.1 status |
|---|---|
| Mock-bank typed tools (4) | ✅ Protected under Contain |
| Generic browser / Playwright clicks | ❌ Not protected, not offered to the agent |
| Shell, filesystem, HTTP fetch | ❌ Not offered to the agent |
| Hosted agents (Claude, ChatGPT, etc.) | ❌ Not supported |
| Real banks | ❌ Never in v0.1 |
