# Release-binary E2E gate (Windows) — design

**Date:** 2026-09-26 · **Owner:** Christopher Chamaletsos · **Status:** approved design, awaiting spec review
**Model:** the helper E2E gate of claude-code-sandbox (`ado_pipelines/scripts/helper-e2e.py`,
`templates/helper-e2e-job.yml`) — drive the *installed release binary* through the real user
journey, fail on the first broken promise, publish a JSON summary + logs.

## Goal

Every Windows release binary (`netbridge.exe` agent, `netbridge-socks.exe` proxy) proves, on a
hosted `windows-latest` runner, that the core journey works with the **PyInstaller-built exe
running from its install location in normal tray mode**:
install → connect (agent ↔ relay ↔ proxy, end-to-end probe green) → traffic through SOCKS5 and
HTTP proxy → relay destination filter → relay restart / reconnect → uninstall.

It catches what the unit tests and the current `--version` / `--import-check` smoke steps cannot:
missing bundled modules on real code paths, frozen-exe subprocess problems (`az.cmd`), installer
and config-location faults, tray-mode startup crashes, protocol drift between the relay and the
two binaries of the same commit.

## Findings that shaped the design

- **Both exes authenticate only via the Azure CLI subprocess** (`shared_auth.token`:
  `check_az_login` → `az account show`, `get_arm_token` → `az account get-access-token`, with the
  executable resolved by `shutil.which("az.cmd")`). The token is checked locally only for its
  `exp` claim (`check_token_expiration`, unverified JWT decode).
- **The relay's `--no-auth` mode** (requires `NETBRIDGE_ALLOW_NO_AUTH=true`, loopback bind only)
  ignores the bearer token and maps every client to `anonymous@local`, so agent and proxy pair
  with each other.
- **The agent blocks loopback destinations by default** (`allow_loopback=False`); private ranges
  are allowed (`allow_private_destinations=True`).
- `netbridge-socks.exe` has **no headless mode** — tray mode only. The agent has `--console`
  (same `NetBridgeApp` without the tray) and `--legacy`.
- Relay endpoints: `/ws` (agent), `/tunnel` (proxy). Configs:
  `%LOCALAPPDATA%\NetBridge\config.json` (`relay_url`, …),
  `%LOCALAPPDATA%\NetBridgeSocks\config.json` (`relay_url`, `socks_port`, `http_port`,
  `probe_target`, …). Both installers register a `HKCU\...\Run` startup entry.

## Decisions

1. **No product code changes; auth is faked at the process boundary.** A fake `az.cmd` (plus a
   small Python helper it calls) is placed first on `PATH` for both exes. It answers
   `account show` with a dummy account JSON and `account get-access-token` with
   `{"accessToken": <unsigned JWT, exp = now + 1h>}`. The binaries therefore run their real,
   unmodified auth path (including the frozen-exe subprocess call); the relay in `--no-auth` mode
   ignores the token. No secrets, no Azure, runs on pull requests.
2. **Relay from the same commit, from source** (`uv run python -m relay --no-auth --host
   127.0.0.1 --port 18080`, `NETBRIDGE_ALLOW_NO_AUTH=true`). Docker on Windows runners cannot run the
   Linux relay image; the relay image itself stays covered by `release-relay.yml` + unit tests.
3. **Target servers on the runner's non-loopback private IPv4** (discovered at runtime), so the
   agent runs with its **default** destination policy (no `allow_loopback`). Targets, all started
   by the driver: an HTTP server (small page + a deterministic 5 MB payload with known sha256), a
   raw TCP echo server, and a listener on a port the relay is told to block.
4. **Real install layout.** The driver copies each exe to its install directory, writes
   `config.json` (`relay_url = ws://127.0.0.1:18080`; the proxy keeps its **default** probe target
   `netbridge-exec:80`, which the agent answers itself — the configuration users run), and launches the exe **from the install location**
   in normal tray mode (the `is_running_installed()` branch — no install dialog).
5. **Driver:** `e2e/netbridge_e2e.py`, run with `uv run` (stdlib only; `socket`/`urllib` for
   SOCKS5 and HTTP proxy clients so no curl-version surprises). Style follows `helper-e2e.py`:
   `step(name, ok, detail)` prints PASS/FAIL and stops on the first failure; best-effort cleanup
   (kill exes, stop relay, `--uninstall`); always writes `e2e-summary.json`.
6. **Where it runs:** a reusable workflow `.github/workflows/e2e-windows.yml`
   (`workflow_call` with optional `version` input; also `pull_request` on changes under
   `relay/ shared/ socks-proxy/ socks-proxy-win/ netbridge-agent/ e2e/` and `workflow_dispatch`).
   It builds **both** exes from the commit (version injected when given), runs the existing
   smoke checks (`--version`, `--import-check`), runs the driver, and uploads the exes plus the
   report/logs as artifacts.
7. **Release workflows publish the tested artifact.** `release-agent.yml` and
   `release-socks-exe.yml` become `e2e` (calls the reusable workflow with the tag version) →
   `publish` (downloads the exe artifact from the same run and releases it). The unit-test step
   stays in the release workflow; the build and smoke steps move into the reusable workflow. No
   second build: the published binary is byte-for-byte the one that passed the gate.

## Journey steps (driver)

| Step | Pass condition |
|------|----------------|
| `fake_az` | the fake `az.cmd` is what `where az.cmd` resolves first; `az account get-access-token` returns a JWT with future `exp` |
| `ports_free` | relay/SOCKS/HTTP ports (18080/11080/13128) are free — a stale process would otherwise answer |
| `relay_up` | relay answers on `127.0.0.1:18080` and the new process is alive |
| `targets_up` | HTTP, echo and blocked-port listeners bound on the private IPv4 |
| `install_agent` / `install_proxy` | exe + `config.json` in place; process started from install dir and still alive after 10 s |
| `agent_connected` | agent log `Status changed: … -> connected` |
| `proxy_connected` | proxy log `Bridge agent reachable - tunnel is working end to end` (end-to-end probe through the agent answered) |
| `relay_paired` | relay `/status` reports ≥1 agent and ≥1 tunnel client |
| `socks5_http` | GET via SOCKS5 (ATYP=domain carrying the target IP) returns the expected page |
| `socks5_dns` | GET via SOCKS5 to `netbridge-e2e-target` (hosts-file name, resolved by the agent) — CI only, skipped without `--target-hostname` |
| `http_connect` | CONNECT via `:3128` to the echo server round-trips bytes |
| `http_forward` | plain `GET http://…` via `:3128` returns the expected page |
| `bulk_payload` | 5 MB download via SOCKS5, sha256 matches |
| `concurrency` | 20 SOCKS5 echo streams open at the same time (relay reports ≥20 active streams) all round-trip |
| `relay_filter` | connection to the blocked port is refused by the proxy (SOCKS5 failure reply / HTTP error), no hang |
| `reconnect` | relay killed and restarted; within 60 s of it being back, traffic flows again and both apps log a new `Connected to relay (session: …)` |
| `uninstall` | `--uninstall` on each exe (driver answers the Yes/No confirmation) exits 0; install dir and `HKCU\...\Run` entry removed |

Stable log markers: the driver matches on log lines the apps already emit (listed above, verified
against the source). If a needed signal has no log line, adding one log statement is the only
permitted product change.

The journey also runs in a **source mode** (relay, agent `--console`, `netbridge-socks serve` from
the checkout) on any OS; CI runs it on Linux for every push/PR, which also verifies the driver
itself before the Windows job runs.

## Risks, verified first in the plan

- **Tray mode on the hosted runner session.** pystray needs a message loop in the runner's
  session. Task 1 of the plan is a spike: start both installed exes in tray mode on
  `windows-latest` and confirm they stay up and connect. Fallback if the tray cannot run: agent
  uses `--console`; for the proxy, add a `--console` mode to `socks-proxy-win` (separate,
  explicitly approved change).
- **Hosted runner has a real Azure CLI** on `PATH`; the fake must shadow it (prepend to `PATH`
  for the launched processes and verify via `where`).
- **Runner private IP** discovery: pick the IPv4 of the default-route interface; fail the
  `targets_up` step clearly if none is found.

## Out of scope

- Real Azure AD auth (token validation, tenant/group checks) — possible later phase with GitHub
  OIDC.
- Linux/macOS proxy (Homebrew, runs from source) and the relay container image.
- Interactive UI: install/URL dialogs, tray menu clicks, notifications.
- Agent auto-update, keep-alive, remote exec and plugins.
