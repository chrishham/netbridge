# End-to-end gate

Drives the whole path — client → proxy (SOCKS5 `:11080`, HTTP `:13128`) → relay → agent → target — and fails on the first broken promise. Reports: `<work>/e2e-summary.json` plus every component's logs in `<work>/logs/`.

| Mode | What runs | Where |
|------|-----------|-------|
| `source` | relay, agent (`--console`) and `netbridge-socks serve` from this checkout | any OS; CI job `e2e-source` on pushes to main and pull requests |
| `exe` | the PyInstaller `netbridge.exe` / `netbridge-socks.exe`, installed to `%LOCALAPPDATA%` and started from there in tray mode | Windows; workflow `e2e-windows.yml` on PRs and before every Windows release |
| `source --relay-image IMG` | as `source`, but the relay runs from a built docker image (`--network host`) | Linux with docker; `release-relay.yml` on PRs and before every image push |

No Azure is involved. The relay runs with auth on: a local key stub signs tokens for the fake az, and an e2e-only `sitecustomize.py` points the relay's key fetch at it. The fake `az` is placed first on `PATH`, so the apps' real auth code path runs and the relay really validates their tokens. Targets listen on the machine's default-route IPv4 because the agent always blocks loopback.

## Run locally

```bash
for p in relay netbridge-agent socks-proxy e2e; do (cd "$p" && uv sync); done
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e
```

Add `--coverage DIR` (source mode, not on Windows) to run the relay, agent and proxy under
coverage: `DIR/summary.md` and the `coverage` key of `e2e-summary.json` show
which product code the journey exercised, per package. It is report-only and
never changes the result; CI's `e2e-source` job shows it in the run summary.

Windows, with built exes (refuses to touch an existing installation unless `--allow-existing-install`):

```powershell
uv run --project e2e python -m netbridge_e2e --mode exe `
  --agent-exe netbridge-agent\dist\netbridge.exe `
  --proxy-exe socks-proxy-win\dist\netbridge-socks.exe --work $env:TEMP\nb-e2e
```

Ports: `--relay-port` (18080), `--socks-port` (11080), `--http-port` (13128); the run refuses to start if any is busy. `--agent-console` runs the agent with `--console` instead of the tray. `--target-hostname NAME` enables the remote-DNS check; map the name to `uv run --project e2e python -m netbridge_e2e.netinfo` in the hosts file first (CI does).

## Steps

`auth_stub_up` → `fake_az` → `ports_free` → `targets_up` → `relay_up` (auth on, key URL redirected) → `auth_matrix` (13 token cases × `/ws`, `/tunnel`: status and rejection reason) → `fault_links_up` → `install_agent` / `install_proxy` → `*_started` → `*_connected` (agent status / proxy's end-to-end probe) → `relay_paired` → `relay_fetched_keys` → `az_called` → `socks5_http` → `socks5_dns` (with `--target-hostname`) → `http_connect` → `http_forward` → `bulk_payload` (5 MiB, sha256) → `concurrency` (20 simultaneous streams) → `relay_filter` (`RELAY_BLOCKED_PORTS`) → `auth_user_isolation` (another user gets no agent; the journey user's open stream keeps working) → `relay_restarted` → `reconnect` → `*_reconnected` → `agent_cut_ends_streams` → `agent_cut_recovers` → `proxy_cut_ends_streams` → `proxy_cut_recovers` → `agent_blackhole_detected` → `relay_unreachable_fails_fast` → `relay_reachable_recovers` → `agent_down_fails_fast` → `agent_restarted` → `uninstall_*` (exe mode; the driver clicks "Yes" on the confirmation).

Both clients reach the relay through in-process fault proxies, so the fault steps can cut, blackhole or refuse each link; heartbeats are shortened to 10 s for the run.

Driver unit tests: `cd e2e && uv run pytest`.
