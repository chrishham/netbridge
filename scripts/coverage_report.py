"""Combine per-component coverage into one repo-relative report.

Run from CI after every component's `uv run pytest --cov`:
    uv run --no-project --with coverage==7.16.2 python scripts/coverage_report.py

Floors are enforced by each component's pytest-cov run and new lines by
diff-cover; this script only reports. It fails only when it cannot produce
the combined report (so main can never go green without one).
"""
import argparse
import math
import os
import subprocess
import sys
import tomllib
from pathlib import Path

COMPONENTS = ("shared", "relay", "netbridge-agent", "socks-proxy", "socks-proxy-win", "e2e")
COMBINED = ".coverage.combined"


def run_coverage(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "coverage", *args], cwd=cwd, capture_output=True, text=True)


def read_floor(comp_dir: Path) -> float | None:
    with open(comp_dir / "pyproject.toml", "rb") as f:
        report = tomllib.load(f).get("tool", {}).get("coverage", {}).get("report", {})
    return report.get("fail_under")


def component_total(comp_dir: Path) -> float:
    # cwd = component so its pyproject [tool.coverage] applies; --fail-under=0 keeps a missed
    # floor from appending "Coverage failure: ..." to stdout (the floor is pytest-cov's job)
    r = run_coverage(["report", "--data-file=.coverage", "--format=total", "--precision=2", "--fail-under=0"], comp_dir)
    if r.returncode != 0:
        raise RuntimeError(f"coverage report in {comp_dir} failed: {r.stderr.strip() or r.stdout.strip()}")
    return float(r.stdout.strip())


def make_row(comp: str, pct: float | None, floor: float | None, error: bool = False) -> dict:
    if error:
        return {"comp": comp, "pct": None, "floor": floor, "status": "error", "hint": ""}
    if pct is None:
        return {"comp": comp, "pct": None, "floor": floor, "status": "no data", "hint": ""}
    if floor is None:
        return {"comp": comp, "pct": pct, "floor": None, "status": "no floor", "hint": ""}
    status = "ok" if pct >= floor else "below floor"
    hint = f"raise fail_under to {math.floor(pct)}" if math.floor(pct) > floor else ""
    return {"comp": comp, "pct": pct, "floor": floor, "status": status, "hint": hint}


def render(rows: list[dict]) -> str:
    lines = ["## Coverage", "", "| Component | Coverage | Floor | Status | Hint |", "|---|---|---|---|---|"]
    for r in rows:
        pct = "—" if r["pct"] is None else f"{r['pct']:.2f}%"
        floor = "—" if r["floor"] is None else f"{r['floor']:g}"
        lines.append(f"| {r['comp']} | {pct} | {floor} | {r['status']} | {r['hint']} |")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    root = Path(p.parse_args(argv).root).resolve()

    rows, data_files = [], []
    for comp in COMPONENTS:
        comp_dir = root / comp
        data = comp_dir / ".coverage"
        floor = read_floor(comp_dir) if (comp_dir / "pyproject.toml").exists() else None
        if not data.exists():
            rows.append(make_row(comp, None, floor))
            continue
        try:
            pct = component_total(comp_dir)
        except (RuntimeError, ValueError) as e:  # an unreadable file is reported, and kept out of combine
            print(e, file=sys.stderr)
            rows.append(make_row(comp, None, floor, error=True))
            continue
        data_files.append(str(data))
        rows.append(make_row(comp, pct, floor))

    table = render(rows)
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(table)

    if not data_files:
        print("no component produced usable coverage data", file=sys.stderr)
        return 1
    # data files hold absolute paths under this checkout; reporting from the root makes them repo-relative
    steps = (["combine", "--keep", f"--data-file={COMBINED}", *data_files],
             ["xml", f"--data-file={COMBINED}", "-o", "coverage.xml"],
             ["html", f"--data-file={COMBINED}", "-d", "htmlcov"])
    for args in steps:
        r = run_coverage(args, root)
        if r.returncode != 0:
            print(f"coverage {args[0]} failed: {r.stderr.strip() or r.stdout.strip()}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
