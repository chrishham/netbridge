"""The E2E journey: every step must pass; the first failure stops the run.

  uv run --project e2e python -m netbridge_e2e --mode source
  uv run --project e2e python -m netbridge_e2e --mode exe --agent-exe netbridge.exe --proxy-exe netbridge-socks.exe

install → connect (relay pairs agent and proxy, fake az used) → SOCKS5 /
HTTP CONNECT / HTTP forward / 5 MiB / 20 parallel streams → relay port
filter → relay restart and reconnect → uninstall (exe mode).
"""
import argparse
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import clients, fakeaz, netinfo
from .procs import IS_WINDOWS
from .stack import CONNECTED, PROXY_READY, RELAY_SESSION, Relay, SourceAgent, SourceProxy, make_exe_agent, make_exe_proxy
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
            self._write_summary(code)
        return code

    def _write_summary(self, code: int) -> None:
        summary = {"mode": self.args.mode, "ok": code == 0, "steps": self.results}
        (self.work / "e2e-summary.json").write_text(json.dumps(summary, indent=2))
        print("\n==== E2E summary ====")
        for r in self.results:
            print(f"  {'✓' if r['ok'] else '✗'} {r['step']}: {r['detail']}")

    # --- the journey -------------------------------------------------------

    def _journey(self) -> None:
        a = self.args
        logs = self.work / "logs"
        logs.mkdir(parents=True, exist_ok=True)
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
        env.update(NO_PROXY=no_proxy, no_proxy=no_proxy)

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

        relay = Relay(logs, a.relay_port, targets.blocked_port, env, image=a.relay_image)
        self.cleanups.append(relay.stop)
        relay.start()
        self.step("relay_up", relay.wait_ready(180), f"{relay.url} {'' if relay.alive() else relay.logs.tail()}")

        agent, proxy = self._components(relay.url, ip, targets, env)
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
        paired = relay.wait_paired(30)
        self.step("relay_paired", paired is not None, json.dumps(paired or relay.status()))

        calls_log = self.work / "az-calls.log"
        calls = calls_log.read_text() if calls_log.exists() else ""
        n = calls.count("account get-access-token")
        self.step("az_called", n >= 2, f"{n} token requests went through the fake az")

        self._traffic(ip, targets, relay)
        self._filter(ip, targets, relay)
        self._reconnect(relay, agent, proxy, ip, targets)

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

    def _components(self, relay_url: str, ip: str, targets: Targets, env: dict):
        a = self.args
        if a.mode == "source":
            return (SourceAgent(self.work, relay_url, env),
                    SourceProxy(self.work, relay_url, a.socks_port, a.http_port, env))
        return (make_exe_agent(Path(a.agent_exe), relay_url, env, self.work,
                               console=a.agent_console, allow_existing=a.allow_existing_install),
                make_exe_proxy(Path(a.proxy_exe), relay_url, a.socks_port, a.http_port,
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
        deadline = start + 60  # the spec's reconnect promise
        last = "never paired"
        recovered = False
        while (left := deadline - time.monotonic()) > 0:
            if relay.wait_paired(min(5, left)):
                try:
                    status, body = self._socks_get(ip, targets, timeout=max(1.0, min(15.0, deadline - time.monotonic())))
                    if status == 200 and body == PAGE:
                        recovered = time.monotonic() <= deadline
                        break
                    last = f"HTTP {status}"
                except Exception as e:  # noqa: BLE001 — retried until the deadline
                    last = f"{type(e).__name__}: {e}"
            time.sleep(min(2, max(0, deadline - time.monotonic())))
        took = time.monotonic() - start
        self.step("reconnect", recovered,
                  f"traffic flows again {took:.0f}s after the relay came back" if recovered
                  else f"no working tunnel within 60s of the relay coming back ({last}; relay {relay.status()})")
        for comp in (agent, proxy):
            m = comp.logs.wait_for(RELAY_SESSION, 10, since=marks[comp.name])
            self.step(f"{comp.name}_reconnected", m is not None, m.group(0) if m else comp.logs.tail())


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
    args = p.parse_args(argv)
    if args.relay_image and args.mode != "source":
        p.error("--relay-image works in source mode only (the image is a Linux container)")
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
