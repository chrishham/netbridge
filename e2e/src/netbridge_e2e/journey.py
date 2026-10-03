"""The E2E journey: every step must pass; the first failure stops the run.

  uv run --project e2e python -m netbridge_e2e --mode source
  uv run --project e2e python -m netbridge_e2e --mode exe --agent-exe netbridge.exe --proxy-exe netbridge-socks.exe

The relay runs with auth on: a local key stub signs the fake az's tokens.
install → connect (relay pairs agent and proxy, fake az used) → auth matrix
→ SOCKS5 / HTTP CONNECT / HTTP forward / 5 MiB / 20 parallel streams → relay
port filter → user isolation → pentest suite (source mode) → relay restart and
reconnect → link faults through in-process fault proxies (cut, blackhole, relay
unreachable, agent down) → uninstall (exe mode).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import clients, fakeaz, netinfo
from .authstub import AuthStub
from .cov import E2ECoverage
from .faultproxy import FaultProxy
from .jwtmint import ISSUER_V2
from .procs import IS_WINDOWS
from .stack import CLIENT_TUNING, CONNECTED, PROXY_READY, REDIRECTED, RELAY_SESSION, REPO, Relay, SourceAgent, SourceProxy, make_exe_agent, make_exe_proxy
from .targets import PAGE, PAYLOAD_SHA256, Targets


OTHER_TENANT = "22222222-2222-2222-2222-222222222222"
OTHER_USER = "other@netbridge.test"
NO_AGENT = "No bridge agent available"
PENTEST_USER = "pentest@netbridge.test"
# not observable here: rate limits are raised on purpose (FAULT_TUNING), session_hijack makes one
# connection without a separation check, stream_id_enumeration is a hard-coded pass
PENTEST_SKIPS = ("rapid_connection_dos", "session_hijack", "stream_id_enumeration")
PENTEST_TIMEOUT = 180


class StepFailed(Exception):
    pass


class Journey:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.work = Path(args.work).resolve()
        self.results: list[dict] = []
        self.cleanups: list = []
        self.socks = ("127.0.0.1", args.socks_port)
        self.http = ("127.0.0.1", args.http_port)
        self.cov = E2ECoverage(Path(args.coverage).resolve()) if args.coverage else None
        self.coverage: dict | None = None
        self._agent_up = 0.0  # monotonic start of the agent's current relay session
        self._agent_up_sessions = 0  # session count when _agent_up was last set

    # --- bookkeeping -------------------------------------------------------

    def step(self, name: str, ok, detail: str = "") -> None:
        self.results.append({"step": name, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}", flush=True)
        if not ok:
            raise StepFailed(name)

    def check(self, name: str, fn) -> None:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001 — any error is a failed step
            ok, detail = False, f"{type(e).__name__}: {e}"
        self.step(name, ok, detail)

    def run(self) -> int:
        self.work.mkdir(parents=True, exist_ok=True)
        code = 1
        try:
            self._journey()
            code = 0
        except StepFailed:
            pass
        except Exception as e:  # noqa: BLE001 — a driver bug fails the gate too
            self.results.append({"step": "driver_error", "ok": False, "detail": f"{type(e).__name__}: {e}"})
            print(f"FAIL  driver_error: {type(e).__name__}: {e}", flush=True)
        finally:
            for fn in reversed(self.cleanups):
                try:
                    fn()
                except Exception as e:  # noqa: BLE001
                    print(f"cleanup: {type(e).__name__}: {e}", flush=True)
            if self.cov:  # processes are stopped now, so their data is flushed (None if prepare failed)
                try:
                    self.coverage = self.cov.finalize()
                except Exception as e:  # noqa: BLE001 — report-only
                    print(f"coverage: {type(e).__name__}: {e}", flush=True)
            self._write_summary(code)
        return code

    def _write_summary(self, code: int) -> None:
        summary = {"mode": self.args.mode, "ok": code == 0, "steps": self.results}
        if self.coverage is not None:
            summary["coverage"] = self.coverage
        (self.work / "e2e-summary.json").write_text(json.dumps(summary, indent=2))
        print("\n==== E2E summary ====")
        for r in self.results:
            print(f"  {'✓' if r['ok'] else '✗'} {r['step']}: {r['detail']}")
        if self.coverage is not None:
            if self.coverage.get("total") is not None:
                print(f"E2E coverage: {self.coverage['total']:.2f}%")
            for w in self.coverage.get("warnings", []):
                print(f"  coverage warning: {w}")

    # --- the journey -------------------------------------------------------

    def _journey(self) -> None:
        a = self.args
        logs = self.work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
        if self.cov:
            try:
                self.cov.prepare()
            except Exception as e:  # noqa: BLE001 — report-only: run uninstrumented
                print(f"coverage disabled: {type(e).__name__}: {e}", flush=True)
                self.coverage = {"total": None, "packages": {}, "warnings": [f"coverage disabled: {type(e).__name__}: {e}"]}
                self.cov = None
        calls_log = self.work / "az-calls.log"
        calls_log.write_text("")  # truncate stale data from reused --work dir

        def get_ip():
            ip = netinfo.private_ipv4()
            return True, ip

        self.check("network", get_ip)
        ip = self.results[-1]["detail"]
        stub = AuthStub(self.work)
        self.cleanups.append(stub.close)
        stub.start()
        self.step("auth_stub_up", True, f"{stub.jwks_url} kid {stub.kid}")
        env = fakeaz.env_with_fake_az(os.environ, sys.executable, calls_log, auth_env=stub.env())
        # strip proxy vars that would route ws://127.0.0.1 through an external proxy
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            env.pop(var, None)
        no_proxy = f"127.0.0.1,localhost,{ip}"
        env.update(NO_PROXY=no_proxy, no_proxy=no_proxy, **CLIENT_TUNING)

        self.check("fake_az", lambda: self._check_fake_az(env))
        busy = [p for p in (a.relay_port, a.socks_port, a.http_port) if netinfo.port_in_use(p)]
        # a stale relay/proxy would answer for the ones we start: false pass
        self.step("ports_free", not busy, f"busy: {busy}" if busy else f"{a.relay_port}, {a.socks_port}, {a.http_port} free")

        # targets_up: create and register cleanup before first failure can occur
        targets = None

        def create_targets():
            nonlocal targets
            targets = Targets(ip)
            self.cleanups.append(targets.close)
            return True, f"http {ip}:{targets.http_port}, echo :{targets.echo_port}, blocked :{targets.blocked_port}"

        self.check("targets_up", create_targets)

        relay = Relay(logs, a.relay_port, targets.blocked_port, env, image=a.relay_image, cov=self.cov, auth=stub)
        self.cleanups.append(relay.stop)
        relay.start()
        ready = relay.wait_ready(180)
        ok, detail = self._relay_auth_on(relay, stub) if ready else (False, "not ready")
        self.step("relay_up", ok, f"{relay.url}; {detail}{'' if relay.alive() else ' ' + relay.logs.tail()}")
        self.check("auth_matrix", lambda: self._auth_matrix(relay, stub))

        agent_link = FaultProxy(("127.0.0.1", relay.port), "agent")
        self.cleanups.append(agent_link.close)
        proxy_link = FaultProxy(("127.0.0.1", relay.port), "proxy")
        self.cleanups.append(proxy_link.close)
        for link in (agent_link, proxy_link):
            link.start()
        self.step("fault_links_up", True, f"agent via :{agent_link.port}, proxy via :{proxy_link.port}")

        agent, proxy = self._components(agent_link.url, proxy_link.url, ip, targets, env)
        for comp in (agent, proxy):
            self.cleanups.append(comp.cleanup)
            self.cleanups.append(lambda c=comp: c.collect_logs(logs))  # runs before cleanup
        self.check("install_agent", lambda: (True, agent.install()))
        self.check("install_proxy", lambda: (True, proxy.install()))

        start_marks = {}
        for comp in (agent, proxy):
            start_marks[comp.name] = comp.logs.mark()  # a reused --work dir must not supply old markers
            comp.start()
            time.sleep(10)
            self.step(f"{comp.name}_started", comp.alive(), "running" if comp.alive() else comp.logs.tail())
        # agent: its app status; proxy: the end-to-end probe through the agent answered
        for comp, marker in ((agent, CONNECTED), (proxy, PROXY_READY)):
            m = comp.logs.wait_for(marker, 120, since=start_marks[comp.name], alive=comp.alive)
            self.step(f"{comp.name}_connected", m is not None, m.group(0) if m else comp.logs.tail())
            if comp is agent:
                self._agent_up = time.monotonic()
                self._agent_up_sessions = self._agent_sessions(agent)
        paired = relay.wait_paired(30)
        self.step("relay_paired", paired is not None, json.dumps(paired or relay.status()))
        self.step("relay_fetched_keys", stub.requests() >= 1, f"{stub.requests()} JWKS fetch(es) by the relay")

        calls_log = self.work / "az-calls.log"
        calls = calls_log.read_text() if calls_log.exists() else ""
        n = calls.count("account get-access-token")
        self.step("az_called", n >= 2, f"{n} token requests went through the fake az")

        self._traffic(ip, targets, relay)
        self._filter(ip, targets, relay)
        self.check("auth_user_isolation", lambda: self._user_isolation(relay, stub, ip, targets))
        self._pentest_step(relay, stub, env, logs)
        self._reconnect(relay, agent, proxy, ip, targets)
        self._faults(relay, agent, proxy, ip, targets, agent_link, proxy_link)

        if a.mode == "exe":
            for comp in (agent, proxy):
                comp.collect_logs(logs)  # uninstall deletes the install dir, logs included
                self.check(f"uninstall_{comp.name}", comp.uninstall)

    def _check_fake_az(self, env: dict) -> tuple[bool, str]:
        az = shutil.which("az.cmd" if IS_WINDOWS else "az", path=env["PATH"])
        if not az or Path(az).resolve().parent != fakeaz.FAKE_AZ_DIR:
            return False, f"az resolves to {az}, not the fake in {fakeaz.FAKE_AZ_DIR}"
        own = {k: v for k, v in env.items() if k != fakeaz.ENV_LOG}  # keep az_called counting the apps only
        out = subprocess.run([az, "account", "get-access-token", "--resource", "https://management.azure.com/"],
                             env=own, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return False, f"exit {out.returncode}: {out.stderr.strip()}"
        left = fakeaz.token_seconds_left(json.loads(out.stdout)["accessToken"])
        return left > 600, f"{az} (token valid {left:.0f}s)"

    def _components(self, agent_url: str, proxy_url: str, ip: str, targets: Targets, env: dict):
        a = self.args
        if a.mode == "source":
            return (SourceAgent(self.work, agent_url, env, cov=self.cov),
                    SourceProxy(self.work, proxy_url, a.socks_port, a.http_port, env, cov=self.cov))
        return (make_exe_agent(Path(a.agent_exe), agent_url, env, self.work,
                               console=a.agent_console, allow_existing=a.allow_existing_install),
                make_exe_proxy(Path(a.proxy_exe), proxy_url, a.socks_port, a.http_port,
                               env, self.work, allow_existing=a.allow_existing_install))

    def _socks_get(self, host: str, targets: Targets, path: str = "/", timeout: float = 15.0) -> tuple[int, bytes]:
        with clients.socks5_connect(self.socks, host, targets.http_port, timeout=timeout) as s:
            return clients.http_get(s, f"{host}:{targets.http_port}", path)

    def _traffic(self, ip: str, targets: Targets, relay: Relay) -> None:
        def socks5_http():
            status, body = self._socks_get(ip, targets)
            return status == 200 and body == PAGE, f"HTTP {status}, {len(body)} bytes"

        def socks5_dns():
            name = self.args.target_hostname
            if not name:
                return True, "skipped: no --target-hostname (IP literal only)"
            resolved = socket.gethostbyname(name)
            if resolved != ip:
                return False, f"{name} resolves to {resolved} here, expected {ip} (hosts entry missing?)"
            status, body = self._socks_get(name, targets)  # the agent resolves the name
            return status == 200 and body == PAGE, f"{name} via remote DNS: HTTP {status}, {len(body)} bytes"

        def http_connect():
            data = b"netbridge-e2e-echo\n" * 1000
            with clients.http_connect(self.http, ip, targets.echo_port) as s:
                got = clients.echo_roundtrip(s, data)
            return got == data, f"{len(got)} bytes echoed"

        def http_forward():
            status, body = clients.http_forward_get(self.http, f"http://{ip}:{targets.http_port}/")
            return status == 200 and body == PAGE, f"HTTP {status}, {len(body)} bytes"

        def bulk_payload():
            status, body = self._socks_get(ip, targets, "/payload", timeout=60)
            digest = hashlib.sha256(body).hexdigest()
            return status == 200 and digest == PAYLOAD_SHA256, f"HTTP {status}, {len(body)} bytes, sha256 {digest[:16]}"

        def concurrency():
            peak: list[dict | None] = []
            # every stream is open before any data moves, and the relay confirms it
            barrier = threading.Barrier(20, action=lambda: peak.append(relay.status()), timeout=60)

            def one(i: int) -> bool:
                data = hashlib.sha256(str(i).encode()).digest() * 2048  # 64 KiB, distinct per stream
                with clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=60) as s:
                    barrier.wait()
                    return clients.echo_roundtrip(s, data) == data

            with ThreadPoolExecutor(20) as pool:
                results = list(pool.map(one, range(20)))
            active = (peak[0] or {}).get("active_streams", 0) if peak else 0
            return all(results) and active >= 20, (f"{sum(results)}/20 streams round-tripped, "
                                                   f"relay saw {active} active streams at once")

        self.check("socks5_http", socks5_http)
        self.check("socks5_dns", socks5_dns)
        self.check("http_connect", http_connect)
        self.check("http_forward", http_forward)
        self.check("bulk_payload", bulk_payload)
        self.check("concurrency", concurrency)

    def _filter(self, ip: str, targets: Targets, relay: Relay) -> None:
        def blocked():
            start = time.monotonic()
            try:
                sock = clients.socks5_connect(self.socks, ip, targets.blocked_port, timeout=30)
            except clients.ProxyError as e:
                logged = relay.logs.wait_for(rf"Blocked port {targets.blocked_port}\b", 5)
                return logged is not None, (f"SOCKS5 reply {e.code} after {time.monotonic() - start:.1f}s, "
                                            f"relay logged the block: {logged is not None}")
            sock.close()
            return False, f"connection to blocked port {targets.blocked_port} was allowed"

        self.check("relay_filter", blocked)

    # --- auth ----------------------------------------------------------------

    def _relay_auth_on(self, relay: Relay, stub: AuthStub) -> tuple[bool, str]:
        redirected = relay.logs.wait_for(REDIRECTED + re.escape(stub.jwks_url) + r"(?!\S)", 10)
        auth_required = (relay.status() or {}).get("auth_required")
        ok = redirected is not None and auth_required is True
        return ok, f"{redirected.group(0) if redirected else 'no key-URL redirect logged'}; auth_required={auth_required}"

    @staticmethod
    def _auth_cases(stub: AuthStub) -> list[tuple[str, str | None, str | None]]:
        """(case, token, reason the 401 body must contain); reason None means the upgrade must succeed (101)."""
        header = stub.mint().split(".")[0]  # valid header: the decoder parses it before the payload
        return [
            ("none", None, "Missing Authorization header"),
            ("garbage", "not-a-jwt", "Invalid JWT format"),
            ("wrong signature", stub.foreign_mint(), "Signature verification failed"),
            ("unknown kid", stub.mint(header={"kid": "other"}), "Signing key not found"),
            ("expired", stub.mint(lifetime=-60), "Token expired"),
            ("not yet valid", stub.mint(nbf=int(time.time()) + 600), "Token not yet valid"),
            ("wrong tenant", stub.mint(tid=OTHER_TENANT, iss=ISSUER_V2.format(tid=OTHER_TENANT)), "Invalid tenant"),
            ("wrong issuer", stub.mint(iss="https://evil.example/"), "Invalid issuer"),
            ("wrong audience", stub.mint(aud="https://graph.microsoft.com"), "Invalid audience"),
            ("no identity", stub.mint(upn=None), "No user identity"),
            ("no kid", stub.mint(header={"kid": None}), "No key ID in token header"),
            ("malformed payload", f"{header}.@@@not-base64@@@.sig", "Token validation failed"),
            ("valid", stub.mint(upn="matrix@netbridge.test"), None),
        ]

    def _auth_matrix(self, relay: Relay, stub: AuthStub) -> tuple[bool, str]:
        cases = self._auth_cases(stub)
        mismatches, total = [], 0
        for path in ("/ws", "/tunnel"):
            for case, token, reason in cases:
                fetched = stub.requests()
                total += 1
                try:
                    status, body = clients.ws_upgrade("127.0.0.1", relay.port, path, token)
                except OSError as e:
                    status, body = None, f"{type(e).__name__}: {e}"
                ok = status == 101 if reason is None else status == 401 and reason in body
                if case == "wrong tenant" and stub.requests() != fetched:
                    ok, body = False, f"{body} (relay fetched keys for a rejected tenant)"
                if not ok:
                    want = "101" if reason is None else f"401 {reason!r}"
                    mismatches.append(f"{case} {path}: HTTP {status} {body!r}, want {want}")
        logged = {name: relay.logs.wait_for(f"{name} auth rejected", 5) is not None for name in ("Agent", "Tunnel")}
        missing = [f"no '{name} auth rejected' relay log line" for name, seen in logged.items() if not seen]
        detail = f"{total - len(mismatches)}/{total} outcomes as expected ({len(cases)} cases x /ws, /tunnel)"
        if mismatches or missing:
            return False, f"{detail}; " + "; ".join(mismatches + missing)
        return True, f"{detail}; wrong tenant fetched no keys; relay logged agent and tunnel rejections"

    def _tunnel_connect(self, relay: Relay, token: str, ip: str, targets: Targets) -> dict:
        """One tcp_connect over a fresh /tunnel session; returns the relay's reply (stream closed if it opened)."""
        ws = clients.WsClient.connect("127.0.0.1", relay.port, "/tunnel", token)
        try:
            stream_id = str(uuid.uuid4())
            ws.send_json({"type": "tcp_connect", "stream_id": stream_id, "host": ip, "port": targets.http_port})
            reply = ws.recv_json(10)
            if reply.get("stream_id") != stream_id:
                return {"success": None, "error": f"reply for another stream: {reply}"}
            if reply.get("success") is True:
                ws.send_json({"type": "tcp_close", "stream_id": stream_id})
            return reply
        finally:
            ws.close()

    def _user_isolation(self, relay: Relay, stub: AuthStub, ip: str, targets: Targets) -> tuple[bool, str]:
        probe = b"isolation-probe\n"
        echo = self._open_echo(ip, targets)  # the journey user's agent is connected: this stream works
        try:
            other = self._tunnel_connect(relay, stub.mint(upn=OTHER_USER), ip, targets)
            mine = self._tunnel_connect(relay, stub.mint(), ip, targets)
            echo_after = clients.echo_roundtrip(echo, probe) == probe
        finally:
            echo.close()
        isolated = (other.get("type") == "tcp_connect_result" and other.get("success") is False
                    and NO_AGENT in str(other.get("error")))
        control = mine.get("type") == "tcp_connect_result" and mine.get("success") is True
        return isolated and control and echo_after, (f"{OTHER_USER}: {json.dumps(other)}; journey user: {json.dumps(mine)}; "
                                                     f"echo stream round-tripped before and after: {echo_after}")

    def _pentest_step(self, relay: Relay, stub: AuthStub, env: dict, logs: Path) -> None:
        if self.args.mode != "source":
            self.step("pentest_suite", True, "skipped: exe mode has no checkout")
            return
        self.check("pentest_suite", lambda: self._pentest(relay, stub, env, logs))

    def _pentest(self, relay: Relay, stub: AuthStub, env: dict, logs: Path) -> tuple[bool, str]:
        """security-tests/pentest_suite.py --strict against the relay; full output in logs/pentest.log."""
        suite = REPO / "security-tests"
        cmd = ["uv", "run", "--project", str(suite), "python", str(suite / "pentest_suite.py"),
               f"ws://127.0.0.1:{relay.port}", "--token", stub.mint(upn=PENTEST_USER), "--strict"]
        for name in PENTEST_SKIPS:
            cmd += ["--skip", name]
        log = logs / "pentest.log"
        with log.open("w", encoding="utf-8") as out:
            try:
                # VIRTUAL_ENV points at the driver's venv: uv would warn that it ignores it
                code = subprocess.run(cmd, stdout=out, stderr=subprocess.STDOUT,
                                      env={k: v for k, v in env.items() if k != "VIRTUAL_ENV"},
                                      timeout=PENTEST_TIMEOUT).returncode
            except subprocess.TimeoutExpired:
                code = None
        text = log.read_text(encoding="utf-8", errors="replace")
        if code == 0:
            return True, "; ".join(m.group(0) for m in re.finditer(r"^(Passed|Failed|Skipped): \d+", text, re.M))
        why = f"timed out after {PENTEST_TIMEOUT}s" if code is None else f"exit {code}"
        return False, f"{why} (log {log}): {text[-600:]}"

    def _reconnect(self, relay: Relay, agent, proxy, ip: str, targets: Targets) -> None:
        marks = {agent.name: agent.logs.mark(), proxy.name: proxy.logs.mark()}
        relay.stop()
        time.sleep(3)
        relay.start()
        self.step("relay_restarted", relay.wait_ready(60), relay.url)
        start = time.monotonic()
        recovered, last = self._wait_traffic(ip, targets, relay, start + 60)  # the spec's reconnect promise
        took = time.monotonic() - start
        self.step("reconnect", recovered,
                  f"traffic flows again {took:.0f}s after the relay came back" if recovered
                  else f"no working tunnel within 60s of the relay coming back ({last}; relay {relay.status()})")
        self._agent_up = time.monotonic()
        self._agent_up_sessions = self._agent_sessions(agent)
        for comp in (agent, proxy):
            m = comp.logs.wait_for(RELAY_SESSION, 10, since=marks[comp.name])
            self.step(f"{comp.name}_reconnected", m is not None, m.group(0) if m else comp.logs.tail())

    def _wait_traffic(self, ip: str, targets: Targets, relay: Relay, deadline: float) -> tuple[bool, str]:
        """Poll until relay pairs and an HTTP GET through the tunnel succeeds by the absolute deadline."""
        last = "never paired"
        while (left := deadline - time.monotonic()) > 0:
            if relay.wait_paired(min(5, left)):
                try:
                    status, body = self._socks_get(ip, targets, timeout=max(1.0, min(15.0, deadline - time.monotonic())))
                    if status == 200 and body == PAGE:
                        on_time = time.monotonic() <= deadline
                        return on_time, "traffic flows" if on_time else "traffic flowed only after the deadline"
                    last = f"HTTP {status}"
                except Exception as e:  # noqa: BLE001 — retried until the deadline
                    last = f"{type(e).__name__}: {e}"
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        return False, last


    # --- link faults -------------------------------------------------------

    def _agent_sessions(self, agent) -> int:
        return len(re.findall(RELAY_SESSION, agent.logs.text()))

    def _await_agent_session(self, relay, agent, min_age: float = 65.0, max_wait: float = 240.0) -> None:
        # the agent resets its reconnect delay only after a 60 s session; if it reconnected
        # on its own while we waited, the session is new and the wait starts over.
        # Bounded: an agent that never holds a session (or dies) must not hang the job.
        seen = self._agent_sessions(agent)
        if seen != self._agent_up_sessions:
            self._agent_up = time.monotonic()
            self._agent_up_sessions = seen
        give_up = time.monotonic() + max_wait
        while (wait := self._agent_up + min_age - time.monotonic()) > 0:
            if not agent.alive() or time.monotonic() >= give_up:
                why = "agent exited" if not agent.alive() else f"no stable agent session after {max_wait:.0f}s"
                raise RuntimeError(f"{why} while waiting for a {min_age:.0f}s session ({seen} relay sessions logged); "
                                   f"{self._evidence(relay, agent)}")
            time.sleep(min(wait, 5, give_up - time.monotonic()))
            now = self._agent_sessions(agent)
            if now != seen:
                seen = self._agent_up_sessions = now
                self._agent_up = time.monotonic()

    def _open_echo(self, ip: str, targets: Targets):
        s = clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=15)
        if clients.echo_roundtrip(s, b"fault-probe\n") != b"fault-probe\n":
            s.close()
            raise RuntimeError("echo round trip failed before the fault")
        return s

    def _attempt(self, ip: str, targets: Targets, limit: float) -> tuple[str, str, float]:
        """One SOCKS CONNECT, capped at `limit` seconds wall-clock (socket timeouts are per operation).

        Returns (kind, detail, finished_at): kind is 'refused' (reply 0x04), 'reply' (another SOCKS
        error reply), 'error' (transport error, no reply), 'ok' (connected) or 'hang'.
        """
        start = time.monotonic()
        out: dict = {}

        def run():
            try:
                s = clients.socks5_connect(self.socks, ip, targets.echo_port, timeout=limit)
            except clients.ProxyError as e:
                out["r"] = ("refused" if e.code == 0x04 else "reply"), f"SOCKS reply {e.code:#04x}"
            except OSError as e:
                out["r"] = "error", f"{type(e).__name__}: {e}"
            else:
                s.close()
                out["r"] = "ok", "connected"
            out["at"] = time.monotonic()

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(limit)
        if "r" not in out:
            return "hang", f"no SOCKS reply within {limit:.0f}s", time.monotonic()
        kind, detail = out["r"]
        return kind, f"{detail} after {out['at'] - start:.1f}s", out["at"]

    def _fails_fast(self, ip, targets, deadline: float, per_attempt: float = 10.0) -> tuple[bool, str]:
        last = "no attempt"
        while (left := deadline - time.monotonic()) > 0:
            kind, last, at = self._attempt(ip, targets, min(per_attempt, left))
            if kind == "refused":
                return at <= deadline, last
            if kind != "ok":
                return False, last
            time.sleep(min(1, max(0, deadline - time.monotonic())))  # still connected through a link that has not noticed yet
        return False, f"never refused before the deadline (last: {last})"

    def _evidence(self, relay, *comps) -> str:
        tails = "; ".join(f"{c.name} log: ...{c.logs.tail(400)!r}" for c in comps)
        return f"relay {relay.status()}; {tails}"

    def _inject(self, link: FaultProxy, how: str) -> tuple[float, int]:
        before = link.active()
        n = link.cut() if how == "cut" else link.blackhole()
        if before < 1 or n < 1:
            raise RuntimeError(f"{link.name} link: {before} active, {how} affected {n} (nothing to fault)")
        return time.monotonic(), n

    def _fail_case(self, front_end: str, host: str, port: int, budget: float) -> tuple[int | str, float]:
        """One connect that is expected to fail, capped at `budget` seconds wall-clock."""
        start = time.monotonic()
        out: dict = {}

        def run():
            try:
                if front_end == "socks5":
                    clients.socks5_connect(self.socks, host, port, timeout=budget + 2).close()
                elif front_end == "http_connect":
                    clients.http_connect(self.http, host, port, timeout=budget + 2).close()
                else:
                    out["r"], _ = clients.http_forward_get(self.http, f"http://{host}:{port}/", timeout=budget + 2)
                    return
                out["r"] = "ok"
            except clients.ProxyError as e:
                out["r"] = e.code
            except OSError as e:
                out["r"] = f"error:{type(e).__name__}"
            except Exception as e:
                out["r"] = f"unexpected:{type(e).__name__}"

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(budget)
        return out.get("r", "hang"), time.monotonic() - start

    def _wait_streams_zero(self, relay, within: float, stable: int = 2) -> tuple[bool, str]:
        deadline = time.monotonic() + within
        zeros = 0
        while True:
            last = (relay.status() or {}).get("active_streams", "unreadable")
            zeros = zeros + 1 if last == 0 else 0
            if zeros >= stable:
                return True, f"active_streams 0 ({stable} consecutive polls)"
            if time.monotonic() >= deadline:
                return False, f"active_streams stuck at {last!r} after {within:.0f}s"
            time.sleep(0.5)

    def _faults(self, relay, agent, proxy, ip, targets, agent_link, proxy_link) -> None:
        def recovered(t0, budget, comp=None, marker=None, mark=None):
            ok, detail = self._wait_traffic(ip, targets, relay, t0 + budget)
            if ok and comp is not None:
                # the log line must be there by the same deadline (timeout 0 still checks once)
                m = comp.logs.wait_for(marker, max(0.0, t0 + budget - time.monotonic()), since=mark)
                ok, detail = m is not None, (f"{detail}; {m.group(0)}" if m else f"{detail}; no new '{marker}' log line")
            ok = ok and time.monotonic() <= t0 + budget
            took = f"{detail} ({time.monotonic() - t0:.0f}s after the fault)"
            return ok, took if ok else f"{took}; {self._evidence(relay, agent, proxy)}"

        def with_evidence(check):
            ok, detail = check()
            return ok, detail if ok else f"{detail}; {self._evidence(relay, agent, proxy)}"

        # 1-2: agent link cut
        self._await_agent_session(relay, agent)
        mark = agent.logs.mark()
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(agent_link, "cut")
        ended = clients.wait_closed(echo, 15)
        echo.close()
        self.step("agent_cut_ends_streams", ended, f"{n} link(s) cut; open stream ended: {ended} "
                  f"after {time.monotonic() - t0:.1f}s" + ("" if ended else f"; {self._evidence(relay, agent, proxy)}"))
        self.check("agent_cut_recovers", lambda: recovered(t0, 45, agent, CONNECTED, mark))
        self._agent_up = time.monotonic()
        self._agent_up_sessions = self._agent_sessions(agent)

        # 3-4: proxy link cut (the agent is unaffected)
        mark = proxy.logs.mark()
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(proxy_link, "cut")
        ended = clients.wait_closed(echo, 5)
        echo.close()
        self.step("proxy_cut_ends_streams", ended, f"{n} link(s) cut; open stream ended: {ended} "
                  f"after {time.monotonic() - t0:.1f}s" + ("" if ended else f"; {self._evidence(relay, agent, proxy)}"))
        self.check("proxy_cut_recovers", lambda: recovered(t0, 45, proxy, RELAY_SESSION, mark))

        # 5: agent link blackholed (half-open)
        self._await_agent_session(relay, agent)
        echo = self._open_echo(ip, targets)
        t0, n = self._inject(agent_link, "blackhole")
        probe: dict = {}
        worker = threading.Thread(target=lambda: probe.update(r=self._attempt(ip, targets, 28)), daemon=True)
        worker.start()
        ended = clients.wait_closed(echo, max(0.0, t0 + 45 - time.monotonic()))
        echo.close()
        ended_after = time.monotonic() - t0
        worker.join(max(0.0, t0 + 30 - time.monotonic()))
        kind, how, at = probe.get("r", ("hang", "no SOCKS reply within 30s", time.monotonic()))
        # the promise: a SOCKS error reply (not a hang, not a bare reset) within 30 s of the fault
        replied = kind in ("refused", "reply") and at <= t0 + 30
        if ended and replied:
            ok, traffic = recovered(t0, 75)
        else:
            ok, traffic = False, f"stream ended: {ended} after {ended_after:.1f}s; CONNECT: {how}"
        self.step("agent_blackhole_detected", ended and replied and ok,
                  f"stream ended: {ended} after {ended_after:.1f}s; CONNECT during blackhole: {how}; {traffic}"
                  + ("" if ended and replied else f"; {self._evidence(relay, agent, proxy)}"))
        self._agent_up = time.monotonic()
        self._agent_up_sessions = self._agent_sessions(agent)

        # 6: relay unreachable for both clients
        self._await_agent_session(relay, agent)
        for link in (agent_link, proxy_link):
            link.refuse(True)
        t0 = time.monotonic()
        counts = [link.cut() for link in (agent_link, proxy_link)]
        if min(counts) < 1:
            raise RuntimeError(f"relay_unreachable: cut affected {counts} (nothing to fault)")
        self.check("relay_unreachable_fails_fast", lambda: with_evidence(lambda: self._fails_fast(ip, targets, t0 + 20)))
        for link in (agent_link, proxy_link):
            link.refuse(False)
        t1 = time.monotonic()
        self.check("relay_reachable_recovers", lambda: recovered(t1, 90))
        self._agent_up = time.monotonic()
        self._agent_up_sessions = self._agent_sessions(agent)

        # 7: agent process down, then restarted
        agent.stop()
        # stop() returns once the process is dead; on Windows it also runs taskkill and a cold
        # PowerShell query, which must not eat the 15 s "refused once the agent is down" budget
        t0 = time.monotonic()

        def agent_down():
            ok, detail = self._fails_fast(ip, targets, t0 + 15)
            agents, linked = (relay.status() or {}).get("agents"), proxy_link.active()
            # the refusal must come from "no agent", not from a proxy that lost the relay
            return ok and agents == 0 and linked >= 1, f"{detail}; relay sees {agents} agent(s); proxy link {linked}"

        self.check("agent_down_fails_fast", lambda: with_evidence(agent_down))
        mark = agent.logs.mark()
        agent.start()
        t1 = time.monotonic()

        def restarted():
            ok, detail = recovered(t1, 60, agent, CONNECTED, mark)
            agents = (relay.status() or {}).get("agents")
            return ok and agents == 1, f"{detail}; relay sees {agents} agent(s)"

        self.check("agent_restarted", restarted)
        self._agent_up = time.monotonic()
        self._agent_up_sessions = self._agent_sessions(agent)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="netbridge_e2e", description="NetBridge end-to-end gate")
    p.add_argument("--mode", choices=["source", "exe"], required=True)
    p.add_argument("--work", default="e2e-work", help="reports, logs and state (default: ./e2e-work)")
    p.add_argument("--relay-port", type=int, default=18080)
    p.add_argument("--socks-port", type=int, default=11080)
    p.add_argument("--http-port", type=int, default=13128)
    p.add_argument("--target-hostname",
                   help="name mapped to this machine's IPv4 in the hosts file; enables the remote-DNS check")
    p.add_argument("--relay-image",
                   help="run the relay from this docker image instead of the checkout (Linux: needs host networking)")
    p.add_argument("--agent-exe", help="exe mode: built netbridge.exe")
    p.add_argument("--proxy-exe", help="exe mode: built netbridge-socks.exe")
    p.add_argument("--agent-console", action="store_true",
                   help="exe mode: run the agent with --console instead of the tray")
    p.add_argument("--allow-existing-install", action="store_true",
                   help="exe mode: overwrite an existing installation (disposable machines only)")
    p.add_argument("--coverage", metavar="DIR",
                   help="source mode, Linux/macOS: run relay, agent and proxy under coverage and report per package in DIR (report-only)")
    args = p.parse_args(argv)
    if args.relay_image and args.mode != "source":
        p.error("--relay-image works in source mode only (the image is a Linux container)")
    if args.coverage and args.mode != "source":
        p.error("--coverage works in source mode only")
    if args.coverage and IS_WINDOWS:
        # Proc.stop uses taskkill /F there and coverage's SIGTERM flush is Unix-only: no data would be written
        p.error("--coverage is not supported on Windows")
    if args.mode == "exe":
        if not IS_WINDOWS:
            p.error("--mode exe runs on Windows only")
        for flag in ("agent_exe", "proxy_exe"):
            value = getattr(args, flag)
            if not value or not Path(value).is_file():
                p.error(f"--{flag.replace('_', '-')} must point to the built exe")
    return args


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # cp1252 consoles vs ✓/✗
    return Journey(parse_args(argv)).run()
