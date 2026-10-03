"""The E2E journey: every step must pass; the first failure stops the run.

  uv run --project e2e python -m netbridge_e2e --mode source
  uv run --project e2e python -m netbridge_e2e --mode exe --agent-exe netbridge.exe --proxy-exe netbridge-socks.exe

install → connect (relay pairs agent and proxy, fake az used) → SOCKS5 /
HTTP CONNECT / HTTP forward / 5 MiB / 20 parallel streams → relay port
filter → relay restart and reconnect → link faults through in-process fault
proxies (cut, blackhole, relay unreachable, agent down) → uninstall (exe mode).
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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import clients, fakeaz, netinfo
from .cov import E2ECoverage
from .faultproxy import FaultProxy
from .procs import IS_WINDOWS
from .stack import CLIENT_TUNING, CONNECTED, PROXY_READY, RELAY_SESSION, Relay, SourceAgent, SourceProxy, make_exe_agent, make_exe_proxy
from .targets import PAGE, PAYLOAD_SHA256, Targets


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
        env = fakeaz.env_with_fake_az(os.environ, sys.executable, calls_log)
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

        relay = Relay(logs, a.relay_port, targets.blocked_port, env, image=a.relay_image, cov=self.cov)
        self.cleanups.append(relay.stop)
        relay.start()
        self.step("relay_up", relay.wait_ready(180), f"{relay.url} {'' if relay.alive() else relay.logs.tail()}")

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
        paired = relay.wait_paired(30)
        self.step("relay_paired", paired is not None, json.dumps(paired or relay.status()))

        calls_log = self.work / "az-calls.log"
        calls = calls_log.read_text() if calls_log.exists() else ""
        n = calls.count("account get-access-token")
        self.step("az_called", n >= 2, f"{n} token requests went through the fake az")

        self._traffic(ip, targets, relay)
        self._filter(ip, targets, relay)
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
        seen, give_up = self._agent_sessions(agent), time.monotonic() + max_wait
        while (wait := self._agent_up + min_age - time.monotonic()) > 0:
            if not agent.alive() or time.monotonic() >= give_up:
                why = "agent exited" if not agent.alive() else f"no stable agent session after {max_wait:.0f}s"
                raise RuntimeError(f"{why} while waiting for a {min_age:.0f}s session ({seen} relay sessions logged); "
                                   f"{self._evidence(relay, agent)}")
            time.sleep(min(wait, 5, give_up - time.monotonic()))
            now = self._agent_sessions(agent)
            if now != seen:
                seen, self._agent_up = now, time.monotonic()

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

        # 7: agent process down, then restarted
        t0 = time.monotonic()
        agent.stop()

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
