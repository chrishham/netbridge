# Topology e2e: the journey behind a TLS reverse proxy

**Status:** draft for review · **Date:** 2026-10-04 · **Branch:** `topology-e2e` (base `958719b`)

## Problem

Today the e2e journey connects agent and proxy straight to the relay over plain `ws://127.0.0.1`. Real users never connect that way. Every deployment we run puts a TLS-terminating reverse proxy in front of the relay:

| | k3s (kantoliana) | QA (NBG, Azure DevOps pipeline 2291) |
|---|---|---|
| In front of the relay | Cloudflare → Traefik ingress | Azure App Service front-end (ARR) |
| Image | tag `relay-v*` → `release-relay.yml` | `git clone` of `main` → `deploy/Dockerfile.netbridge` → ACR → web app |
| Relay settings | manifest env | `settings.QA.json` (empty: all defaults) |

What these deployments do differently from the e2e, and what the code depends on:

1. **TLS terminates at the proxy.** Clients use `wss://` and verify the certificate. The relay serves plain HTTP.
2. **The WebSocket upgrade passes through an HTTP proxy**, which forwards the request head and then relays bytes.
3. **Every client reaches the relay from the proxy's address.** That is why #27 had to move the per-IP limit behind authentication.
4. **The proxy appends `X-Forwarded-For`.** Traefik appends a bare IP. App Service appends `ip:port`.
5. **The proxy closes idle connections.** The exact timeout differs: Cloudflare and App Service both close quiet connections after a few minutes or less. Only heartbeats keep a quiet tunnel alive.
6. **The relay may be mounted under a path prefix.** `normalize_relay_url` keeps a path that is given explicitly. No current deployment uses this.

None of these is exercised end to end. The design must not assume one topology: the relay also runs in environments we don't operate.

## Goal

The full journey runs with an **edge** in front of the relay. The edge is a TLS reverse proxy whose behaviours (1-6) are parameters, not a particular product. The journey also proves the trusted-proxy client IP from #27 through a real proxy hop.

## Non-goals

- Testing Traefik, nginx, ARR or Cloudflare themselves. Their configuration belongs to the deployer. We test the properties our code relies on.
- HTTP/2 or HTTP/3 WebSockets (RFC 8441). No current deployment uses them toward the relay.
- Sharing the edge's real certificate with any environment. The e2e uses a CA generated for each run.
- Changing deploy pipelines. Pinning the QA pipeline to a tag is recommended separately (see "Related").

## Design

### The edge (`e2e/src/netbridge_e2e/edgeproxy.py`)

The edge is an in-process proxy in the driver, written in the same style as `faultproxy.py`: threads, `socket` and `ssl`, with no binaries and no root. It runs the same way on the Linux runner and the Windows runner, so source mode and exe mode both use it.

For each accepted connection, the edge:

1. **Terminates TLS** with a server certificate for `localhost` and `127.0.0.1`, signed by a CA created for the run.
2. **Reads the HTTP/1.1 request head**, up to 16 KiB. If the head is malformed or too large, it answers `400` and closes.
3. **Rewrites the head:**
   - It appends the peer to `X-Forwarded-For`, either as `ip` or as `ip:port` (`xff_port` option). Existing fields from the client are kept, as Traefik and ARR keep them.
   - If a `prefix` is configured, it removes that prefix from the path. A request outside the prefix gets `404`.
   - It sets `X-Forwarded-Proto: https`.
4. **Opens plain TCP to the relay**, sends the rewritten head, and then pumps bytes in both directions without interpreting frames. Ping and pong pass through, just as they do through a real proxy after an upgrade.
5. **Closes both sides after `idle_timeout` seconds** in which no byte moves in either direction.

Options are `xff_port: bool`, `prefix: str` and `idle_timeout: float`. The edge counts accepted connections and idle closes, so steps can assert on those counts.

TLS material comes from `cryptography`, which the e2e environment already has through `shared`. The CA is written to `work/edge/ca.pem`. Nothing is installed into an OS trust store.

### Wiring

The current wiring is:

```
client → FaultProxy → relay
```

With `--edge`, it becomes:

```
client --wss--> FaultProxy (TCP) --> edge (TLS, HTTP) --ws--> relay
```

- The fault links stay on the client side of the edge. A cut or a blackhole then behaves like a network fault between the user and the proxy, which is the realistic place for one. Fault steps work unchanged, because the FaultProxy forwards TLS bytes as readily as plain ones.
- Clients get `NETBRIDGE_CA_BUNDLE=work/edge/ca.pem`. Both the agent and the proxy build their SSL context in `shared_auth.connection.create_tunnel_ssl_context`. That function adds this CA to the default store and keeps verification on. No `NETBRIDGE_VERIFY_SSL=false` is used anywhere.
- The client relay URL becomes `wss://localhost:<link port><prefix>/ws` for the agent and `/tunnel` for the proxy. The URL always includes the explicit path, as the edge's prefix option requires.
- The relay gets `RELAY_TRUSTED_PROXIES=127.0.0.1/32` and `RELAY_CLIENT_IP_HEADER=X-Forwarded-For`.
- The driver's own probes, the auth matrix and the pentest suite keep talking to the relay directly. They test the relay, not the path.

Profiles keep both clouds' quirks covered without doubling CI time:

| Mode | Edge profile |
|---|---|
| source (Linux) | `xff_port=False`, `prefix=""`: Traefik-like |
| exe (Windows) | `xff_port=True`, `prefix="/netbridge"`: ARR-like, plus a path prefix |

`--edge-profile {traefik,arr}` overrides the default for local runs.

### New journey steps (edge runs only)

- **`edge_up`:** the edge serves TLS with the run's CA, and an HTTPS `GET /status` through it returns 200.
- **`edge_client_ip`:** proves that the relay keys failed auth on the forwarded client, through the real hop.
  - A bad-token upgrade through the edge carries a client-supplied `X-Forwarded-For: 198.51.100.7`. The edge appends `127.0.0.1` (with a port in the ARR profile). The relay must log `auth rejected for 198.51.100.7`.
  - Flood with `198.51.100.7` until the first 429. The cap is the per-IP override plus 10, as in `auth_flood_spares_valid_users`.
  - A bad token from `198.51.100.8` must then still get 401: buckets are separate per forwarded client.
  - A valid token from `198.51.100.7` must still upgrade (101).

  Here, the client-supplied XFF stands in for an upstream hop. In production, the outermost trusted proxy is the one that writes it.
- **`edge_idle_survives`:** with no user traffic, wait `idle_timeout + 5` s, using an e2e `idle_timeout` of 25 s against heartbeats of 10 s. Then check that:
  - the edge counted no idle closes;
  - neither client logged a new relay session;
  - an echo round trip through the SOCKS port succeeds.
- **`edge_idle_closes_dead_link`:** this is the counter-proof that the idle timer is real. A raw TLS connection through the edge with no traffic must be closed by the edge within `idle_timeout + 5` s.

Every existing step runs unchanged through the edge. That includes the socks5 and HTTP paths, the errors, isolation, the flood, relay restart and reconnect, and all link faults. Because they still pass, the edge adds no breakage.

### Default (no `--edge`) runs

These runs behave exactly as today: plain `ws://`, no edge, and `RELAY_TRUSTED_PROXIES` unset. They keep proving the default configuration that QA runs, in which the relay keys on the peer.

### CI

- **`ci.yml`:**
  - `e2e-source` stays as it is (plain).
  - A new job, `e2e-edge`, runs `--mode source --edge` on `ubuntu-latest` in parallel, with a 20-minute timeout.
  - `release-relay.yml` keeps its plain run against the built image. With `--relay-image` the relay runs in docker on the host network, so the edge in front of it works the same way. Adding `--edge` there is a one-flag follow-up, and the plan decides whether to do it.
- **`e2e-windows.yml`:** switches to `--mode exe --edge`. Installed exes over `wss://` with a verified certificate is how real users connect, and plain `ws://` on Windows adds nothing that the Linux plain run doesn't already prove. The release gate therefore tests the real connection path.

## Risks and how the design handles them

- **CA trust in the frozen exes.** Both exes go through `create_tunnel_ssl_context`, so `NETBRIDGE_CA_BUNDLE` applies. The plan's first task proves this on the Windows runner before anything else depends on it.
- **The edge's own bugs look like product bugs.** The edge gets unit tests (head parsing, the XFF append in both forms, prefix strip and 404, the idle close, oversized heads) before the journey uses it. A failing step names the hop in its detail ("via edge").
- **Timing on slow runners.** The idle steps add about 60 s. Heartbeat 10 s against idle 25 s leaves more than two missed beats of margin.
- **Hostname verification.** Clients connect to `localhost`, and the certificate carries both a `localhost` DNS SAN and a `127.0.0.1` IP SAN. A Windows runner that resolves `localhost` to `::1` first is handled by the edge listening on both families, or by the plan using `127.0.0.1` in the URL.

## Related (not part of this work)

- **QA pipeline pinning:** `pipelines/net-bridge.yaml` clones `main` HEAD. Cloning a `relay-v*` tag would make QA images match tested releases. This change is in the chamaletsos repo and is the owner's call.
- **k3s infra:** restrict 80/443 to Cloudflare, close 6443, and add a NetworkPolicy before trusting the pod range.

## Success criteria

1. `--mode source --edge` and `--mode exe --edge` pass every step, including the four new ones, locally and in CI.
2. The default plain runs are unchanged and green.
3. The edge's unit tests cover every option. `scripts/coverage.sh` floors hold.
4. No product code changes are needed. If one turns out to be needed, it is a real compatibility finding and gets its own fix and test.
