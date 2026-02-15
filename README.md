# NetBridge

Access internal corporate resources from your laptop by tunneling TCP connections through a remote machine's network position.

## Architecture

```
┌─────────── Laptop ─────────┐    ┌── Azure App Service ──┐    ┌──────── Win Machine ──────┐
│                            │    │                       │    │                           │
│  Browser      Proxy        │    │ Relay                 │    │  Agent          Internal  │
│  kubectl ◄──► SOCKS5 :1080 │◄──►│ WebSocket Multiplexer │◄──►│  WebSocket ◄──► hosts     │
│  CLI          HTTP  :3128  │    │                       │    │  TCP tunnel               │
│                            │    │                       │    │                           │
└────────────────────────────┘    └───────────────────────┘    └───────────────────────────┘
```

## Quick Start

### 1. Agent (Windows)

Download [`netbridge.exe`](https://github.com/chrishham/netbridge/releases/latest) and run it on the Windows machine. A dialog will prompt for your relay URL. The agent installs itself, registers for Windows Startup, and connects automatically.

The tray icon shows connection status: green (connected), yellow (connecting), red (disconnected), orange (login required).

### 2. Proxy (macOS / Linux / WSL)

Requires [Homebrew](https://brew.sh). If you don't have it:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then install the proxy:

```bash
brew tap chrishham/tap
brew install netbridge-socks
```

Continue with these instructions: [homebrew-tap README](https://github.com/chrishham/homebrew-tap#netbridge-socks).

## Proxy Usage

The proxy exposes two local endpoints:
- **SOCKS5** on `localhost:1080`
- **HTTP** on `localhost:3128`

### Browser (Firefox)

1. Settings → Network Settings → Manual proxy
2. SOCKS Host: `localhost`, Port: `1080`, SOCKS v5
3. Check "Proxy DNS when using SOCKS v5"

### kubectl

```bash
# in ~/.kube/config under cluster
clusters:
- cluster:
    server: https://your-k8s-cluster.example.com:6443
    proxy-url: socks5://localhost:1080
```

### HTTP Proxy (Node.js, npm, git, go)

```bash
# Bash/Zsh
export HTTP_PROXY="http://localhost:3128"
export HTTPS_PROXY="http://localhost:3128"

# git over HTTPS
git config --global http.proxy http://localhost:3128
```

### curl

```bash
# Via SOCKS5 (socks5h resolves DNS through the proxy)
curl --proxy socks5h://localhost:1080 https://internal-api.example.com/health

# Via HTTP proxy
curl --proxy http://localhost:3128 https://internal-api.example.com/health
```

### Remote Access

By default the proxy binds to localhost only. To allow connections from other machines:

```bash
netbridge-socks --relay <URL> --host 0.0.0.0 --allow-remote --proxy-auth user:pass
```

`--allow-remote` requires `--proxy-auth` to prevent open proxy abuse.

## Configuration

### Agent

The agent loads configuration from `%LOCALAPPDATA%\NetBridge\config.json`:

| Field | Description | Default |
|-------|-------------|---------|
| `relay_url` | Relay hostname or full WebSocket URL | — |
| `auto_connect` | Connect to relay on startup | `true` |
| `show_notifications` | Show desktop notifications | `true` |
| `log_level` | `DEBUG`, `INFO`, `WARNING`, `ERROR` | `"INFO"` |
| `proxy.http` | HTTP proxy URL (auto-detected if `null`) | `null` |
| `proxy.https` | HTTPS proxy URL (auto-detected if `null`) | `null` |

Proxy settings are auto-detected from the system (PAC file / WinHTTP) per target URL.

### Relay

The relay is configured entirely through environment variables.

**Authentication:**

| Variable | Description | Default |
|----------|-------------|---------|
| `NETBRIDGE_ALLOWED_TENANTS` | Comma-separated Azure AD tenant IDs (required) | — |
| `NETBRIDGE_ALLOWED_USERS` | Comma-separated allowed user emails | all users in tenant |
| `NETBRIDGE_ALLOWED_GROUPS` | Comma-separated allowed Azure AD group IDs | all groups |
| `NETBRIDGE_MAX_TOKEN_AGE_HOURS` | Reject tokens issued more than N hours ago | `0` (disabled) |
| `NETBRIDGE_ALLOW_NO_AUTH` | Set to `true` to permit `--no-auth` (loopback only) | `false` |

**Rate Limiting:**

| Variable | Description | Default |
|----------|-------------|---------|
| `RELAY_RATE_CONNECTIONS_PER_MIN` | Max WebSocket connections per user per minute | `10` |
| `RELAY_RATE_MESSAGES_PER_SEC` | Max messages per user per second | `100` |
| `RELAY_RATE_STREAMS_PER_MIN` | Max new TCP streams per user per minute | `50` |
| `RELAY_RATE_IP_CONNECTIONS_PER_MIN` | Max connections per IP per minute (pre-auth) | `30` |
| `RELAY_MAX_ACTIVE_STREAMS` | Global maximum concurrent TCP streams | `500` |
| `RELAY_GLOBAL_BANDWIDTH_LIMIT_MBPS` | Global bandwidth cap in Mbps (`0` = unlimited) | `0` |

**Destination Filtering:**

| Variable | Description | Default |
|----------|-------------|---------|
| `RELAY_BLOCKED_PORTS` | Comma-separated blocked TCP ports (e.g. `3389,22`) | — |
| `RELAY_DENIED_DESTINATIONS` | Comma-separated CIDRs / hostname globs to deny | — |
| `RELAY_ALLOWED_DESTINATIONS` | Comma-separated CIDRs / hostname globs to allow (allowlist mode) | — |

When `RELAY_ALLOWED_DESTINATIONS` is set only matching destinations are reachable. The deny list is checked first.

**Timeouts:**

| Variable | Description | Default |
|----------|-------------|---------|
| `RELAY_HEARTBEAT_INTERVAL` | WebSocket ping interval in seconds | `30` |
| `RELAY_STREAM_TIMEOUT` | Idle stream timeout in seconds | `120` |
| `RELAY_CLEANUP_INTERVAL` | Stale-stream sweep interval in seconds | `30` |
| `RELAY_MAX_MESSAGE_SIZE` | Maximum WebSocket message size in bytes | `1048576` (1 MB) |

**Logging:**

| Variable | Description | Default |
|----------|-------------|---------|
| `RELAY_LOG_FORMAT` | `json` for structured JSON output, `text` for human-readable | `text` |

### Changing the Relay URL

**Agent:** right-click the tray icon → **Change Relay URL**. The agent restarts automatically.

**Proxy:** see the [homebrew-tap README](https://github.com/chrishham/homebrew-tap#netbridge-socks) for config file location.

Run `netbridge-socks --help` for all proxy CLI options.

## Security Notes

- This is **not** a shell or RCE tool — it only tunnels TCP connections
- All traffic is encrypted (TLS) between each component and the relay
- No credentials are stored or transmitted — authentication uses Azure CLI tokens at runtime
- Both proxy servers bind to localhost only by default
- Authentication uses Azure AD ARM tokens (`az login`)
- When behind a TLS-intercepting proxy, prefer `--ca-bundle <file>` (or `NETBRIDGE_CA_BUNDLE` env var) to supply your corporate CA certificate instead of disabling verification entirely
- SSL verification can be disabled (`--no-verify-ssl`) as a **last resort** — this requires setting `NETBRIDGE_ALLOW_INSECURE=1` and weakens security

## Development

Each component is a separate Python package managed with `uv`:

```bash
cd <component>

# Run the component (use --native-tls in corporate environments)
uv run --native-tls <component-name>

# Run tests
uv run --native-tls pytest
```

## Releasing

Each component is versioned and released independently:

```bash
# Release the agent (builds Windows .exe and creates a GitHub Release)
git tag agent-v0.5.0 && git push --tags

# Release the relay (builds and pushes Docker image to GHCR)
git tag relay-v1.0.0 && git push --tags

# Release the socks proxy (runs tests and updates Homebrew formula)
git tag socks-v0.2.0 && git push --tags
```
