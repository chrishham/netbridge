"""Report-only coverage of the source-mode journey (--coverage DIR).

Each component runs under `coverage run` with its own venv interpreter: through
`uv run` the direct child would be uv, and Proc.stop SIGKILLs the group right
after uv exits — before Python's atexit flush.
"""
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from .stack import REPO, _uv

PROBE_TIMEOUT = 120

PACKAGES = {
    "relay": "relay/src/relay",
    "netbridge_agent": "netbridge-agent/src/netbridge_agent",
    "socks_proxy": "socks-proxy/src/socks_proxy",
    "shared_auth": "shared/src/shared_auth",
}


class E2ECoverage:
    def __init__(self, dir: Path, repo: Path = REPO):
        self.dir = dir
        self.repo = repo
        self.rcfile = dir / "coveragerc"  # no leading dot: prepare() deletes .coverage*
        self.warnings: list[str] = []
        self._pythons: dict[str, str] = {}

    def prepare(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        # a reused dir must not count an earlier run's data or show its reports as current
        owned = (".coverage", "coverage.json", "coverage.xml", "summary.md")
        for f in [*self.dir.glob(".coverage.*"), *(self.dir / n for n in owned)]:
            f.unlink(missing_ok=True)
        # shared_auth is a non-editable copy in each venv's site-packages
        paths = "".join(f"{pkg} =\n    {self.repo / rel}\n    */site-packages/{pkg}\n" for pkg, rel in PACKAGES.items())
        self.rcfile.write_text(
            "[run]\nbranch = true\nparallel = true\nsigterm = true\n"
            f"source_pkgs = {', '.join(PACKAGES)}\n"
            f"data_file = {self.dir / '.coverage'}\n\n"
            f"[paths]\n{paths}")

    def _python(self, project: str) -> str:
        if project not in self._pythons:
            # one call resolves the venv interpreter AND proves coverage imports there, parses
            # the rcfile and can start tracing (data_file=None: nothing written), so a broken
            # setup falls back instead of killing the child
            probe = ("import sys, coverage; c = coverage.Coverage(config_file=sys.argv[1], data_file=None); "
                     "c.start(); c.stop(); print(sys.executable)")
            # start_new_session creates a process group so we can kill descendants on timeout
            # (--coverage is rejected on Windows in parse_args, so POSIX-only killpg is fine)
            p = subprocess.Popen(_uv(project, "python", "-c", probe, str(self.rcfile)),
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 start_new_session=True)
            try:
                stdout, stderr = p.communicate(timeout=PROBE_TIMEOUT)
            except subprocess.TimeoutExpired:
                # kill the whole process group (uv + its Python child)
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                p.communicate()  # reap
                raise
            if p.returncode != 0:
                raise subprocess.CalledProcessError(p.returncode, p.args, stdout, stderr)
            self._pythons[project] = stdout.strip().splitlines()[-1]
        return self._pythons[project]

    def wrap(self, project: str, module_args: list[str]) -> list[str] | None:
        try:
            python = self._python(project)
        except Exception as e:  # noqa: BLE001 — report-only: caller runs uninstrumented
            self.warn(f"{project}: cannot resolve venv python ({type(e).__name__}: {e}); not instrumented")
            return None
        return [python, "-m", "coverage", "run", f"--rcfile={self.rcfile}", *module_args]

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def finalize(self) -> dict:
        result = {"total": None, "packages": dict.fromkeys(PACKAGES), "warnings": self.warnings}
        try:
            self._combine_into(result)
        except Exception as e:  # noqa: BLE001 — report-only: never fail the journey
            self.warn(f"coverage combine/report failed: {type(e).__name__}: {e}")
        for pkg, pct in result["packages"].items():
            if pct is None:
                self.warn(f"no coverage data for {pkg}")
        try:
            self._write_markdown(result)
        except OSError as e:
            self.warn(f"cannot write summary.md: {e}")
        return result

    def _coverage(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "coverage", *args, f"--rcfile={self.rcfile}"],
                              cwd=self.repo, capture_output=True, text=True, timeout=300)

    def _combine_into(self, result: dict) -> None:
        if not list(self.dir.glob(".coverage.*")):
            raise RuntimeError("no data files (did any component start under coverage?)")
        for args in (("combine",), ("json", "-o", str(self.dir / "coverage.json")),
                     ("xml", "-o", str(self.dir / "coverage.xml"))):
            r = self._coverage(*args)
            if r.returncode != 0:
                raise RuntimeError(f"coverage {args[0]}: {r.stderr.strip() or r.stdout.strip()}")
        data = json.loads((self.dir / "coverage.json").read_text())
        result["total"] = round(data["totals"]["percent_covered"], 2)
        sums = {pkg: [0, 0] for pkg in PACKAGES}  # covered, total (lines + branches)
        for name, f in data["files"].items():
            path = (self.repo / name).resolve()
            for pkg, rel in PACKAGES.items():
                if path.is_relative_to((self.repo / rel).resolve()):
                    s = f["summary"]
                    sums[pkg][0] += s["covered_lines"] + s.get("covered_branches", 0)
                    sums[pkg][1] += s["num_statements"] + s.get("num_branches", 0)
        for pkg, (hit, total) in sums.items():
            if total:
                result["packages"][pkg] = round(100 * hit / total, 2)

    def _write_markdown(self, result: dict) -> None:
        def pct(v):
            return "—" if v is None else f"{v:.2f}%"
        lines = ["## E2E coverage (report-only)", "", "| Package | Coverage |", "|---|---|",
                 f"| **total** | {pct(result['total'])} |"]
        lines += [f"| {pkg} | {pct(v)} |" for pkg, v in result["packages"].items()]
        if result["warnings"]:
            lines += ["", *(f"- ⚠ {w}" for w in result["warnings"])]
        (self.dir / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
