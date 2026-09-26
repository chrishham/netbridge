"""Process-tree and log helpers for everything the driver launches."""
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

IS_WINDOWS = sys.platform == "win32"


class Proc:
    """A process tree (uv run → python, PyInstaller bootloader → app) with its output in a file."""

    def __init__(self, name: str, argv: list[str], log_path: Path, env: dict | None = None, cwd: Path | None = None):
        self.name = name
        self.argv = argv
        self.log_path = log_path
        self.env = env
        self.cwd = cwd
        self.popen: subprocess.Popen | None = None
        self._log = None

    def start(self) -> "Proc":
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self.log_path, "ab")
        group = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if IS_WINDOWS else {"start_new_session": True}
        self.popen = subprocess.Popen(
            self.argv, cwd=self.cwd, env=self.env,
            stdin=subprocess.DEVNULL, stdout=self._log, stderr=subprocess.STDOUT, **group,
        )
        return self

    def alive(self) -> bool:
        return self.popen is not None and self.popen.poll() is None

    def stop(self, timeout: float = 10.0) -> None:
        if self.popen is None:
            return
        pid = self.popen.pid
        if IS_WINDOWS:
            if self.popen.poll() is None:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
        else:
            _killpg(pid, signal.SIGTERM)
        try:
            self.popen.wait(timeout)
        except subprocess.TimeoutExpired:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True)
            else:
                _killpg(pid, signal.SIGKILL)
            self.popen.wait(5)
        if not IS_WINDOWS:
            _killpg(pid, signal.SIGKILL)  # stragglers left in the group
        if self._log:
            self._log.close()
            self._log = None


def _killpg(pid: int, sig: int) -> None:
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        pass


def kill_exe_path(path: Path) -> None:
    """Kill processes running exactly this executable (Windows; PyInstaller onefile leftovers).

    Matches the full path, never the image name: another installation of the
    same app elsewhere on the machine is left alone.
    """
    if not IS_WINDOWS:
        return
    script = ("Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -eq $env:E2E_KILL_PATH } | "
              "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   env=dict(os.environ, E2E_KILL_PATH=str(path)), capture_output=True, timeout=60)


class LogWatch:
    """Poll one or more log files (paths or glob patterns) for a regex."""

    def __init__(self, *patterns: Path):
        self.patterns = patterns

    def files(self) -> list[Path]:
        found: list[Path] = []
        for p in self.patterns:
            if any(ch in p.name for ch in "*?["):
                found += sorted(p.parent.glob(p.name))
            elif p.exists():
                found.append(p)
        return found

    def mark(self) -> dict[Path, int]:
        return {f: f.stat().st_size for f in self.files()}

    def text(self, since: dict[Path, int] | None = None) -> str:
        parts = []
        for f in self.files():
            try:
                with open(f, "rb") as fh:
                    fh.seek((since or {}).get(f, 0))
                    parts.append(fh.read().decode("utf-8", errors="replace"))
            except OSError:
                continue
        return "".join(parts)

    def wait_for(self, pattern: str, timeout: float, since=None, alive=None) -> re.Match | None:
        rx = re.compile(pattern)
        deadline = time.monotonic() + timeout
        while True:
            m = rx.search(self.text(since))
            if m:
                return m
            if time.monotonic() >= deadline or (alive is not None and not alive()):
                return None
            time.sleep(0.5)

    def tail(self, n: int = 1500) -> str:
        return self.text()[-n:]
