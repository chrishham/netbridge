# Coverage Baseline + Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure line+branch coverage in every component, enforce a ratcheted per-component floor and ≥80% diff coverage on PRs, run `socks-proxy-win` tests in CI, block non-loopback connects in unit tests, and report which product lines the source-mode e2e journey exercises.

**Architecture:** Per-component `[tool.coverage]` config + `pytest-cov` (floor enforced by `pytest --cov`). A stdlib script combines per-component data into one repo-relative `coverage.xml` for diff-cover and writes a markdown table to the job summary. The e2e driver gains `--coverage DIR`, which launches relay/agent/proxy under `coverage run` with their venv interpreter and summarises per-package results.

**Tech Stack:** Python 3.14, uv, pytest, pytest-cov 7.1.0 (coverage 7.16.2), pytest-socket 0.8.1, diff-cover 10.6.0, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-03-coverage-gate-design.md`

## Global Constraints

- Always use `uv` (never bare `python`/`pip`); Python `>=3.14`.
- Components: `shared` (pkg `shared_auth`), `relay` (`relay`), `netbridge-agent` (`netbridge_agent`), `socks-proxy` (`socks_proxy`), `socks-proxy-win` (`socks_proxy_win`), `e2e` (`netbridge_e2e`).
- Coverage config per component: `branch = true`, `source = ["src/<pkg>"]`, `fail_under = floor(measured %)`, `precision = 2`, `show_missing = true`, `skip_covered = true`. No `omit`.
- `--cov` is NOT in `addopts`; plain `uv run pytest` must not measure or enforce coverage.
- pytest-socket only in the five product components (not `e2e`), via `addopts = "--allow-hosts=127.0.0.1,::1,localhost"`; never `--disable-socket`. Broken tests are fixed with fakes; an exemption needs `@pytest.mark.enable_socket` plus a comment why.
- diff-cover threshold: `--fail-under=80`, PRs only, compared to `origin/<base_ref>`.
- Pinned report tool versions: `coverage==7.16.2`, `diff-cover==10.6.0`.
- E2E coverage is report-only: it must never change the journey's exit code.
- No auto-commit from CI; raising floors is a manual edit.
- Commit messages: plain human style, no Claude attribution lines.
- Follow existing code style: compact, sparse comments that explain *why*.

## Review Focus

- A component whose coverage is exactly at/just below its floor (e.g. 46.6% vs floor 47) must fail — pinned by Task 1 Step 6 (precision check) and Task 3's `test_hint_uses_two_decimals`.
- `coverage report` exits 2 and appends "Coverage failure: ..." to stdout when below `fail_under`; the report script must still read the number (it passes `--fail-under=0`) — pinned in Task 3 `test_below_floor_still_reports_total`.
- A reused e2e `--work`/`--coverage` dir with stale `.coverage.*` files must not inflate totals and must not delete `coveragerc` — pinned in Task 5 `test_prepare_removes_only_data_files`.
- A component that dies or is SIGKILLed during the journey produces no data; it must show as a warning, not a crash — pinned in Task 5 `test_finalize_warns_for_packages_without_data` and `test_finalize_never_raises`.
- `shared_auth` code runs from each venv's `site-packages` copy; e2e results must map it back to `shared/src/shared_auth` — pinned in Task 5 `test_rcfile_maps_site_packages_shared_auth`.

---

### Task 1: Coverage config in all components (+ socks-proxy-win on Linux)

**Files:**
- Modify: `shared/pyproject.toml`, `relay/pyproject.toml`, `netbridge-agent/pyproject.toml`, `socks-proxy/pyproject.toml`, `socks-proxy-win/pyproject.toml`, `e2e/pyproject.toml`
- Create: `socks-proxy-win/tests/conftest.py`
- Modify (lockfiles, regenerated): `*/uv.lock`

**Interfaces:**
- Produces: in each component, `uv run pytest --cov` measures `src/<pkg>` with branches and fails below `[tool.coverage.report] fail_under`. Writes `<component>/.coverage`.

- [ ] **Step 1: Make socks-proxy-win collectable on Linux**

Create `socks-proxy-win/tests/conftest.py`:

```python
import os

# pystray picks its backend at import time; on Linux the AppIndicator backend
# needs Gtk, which CI runners and headless dev boxes lack. The dummy backend
# never draws, so the tests stay platform-neutral.
os.environ.setdefault("PYSTRAY_BACKEND", "dummy")
```

Run: `cd socks-proxy-win && uv run pytest -q`
Expected: `103 passed`.

- [ ] **Step 2: Add pytest-cov to every component's dev group**

For each of the six components run (this edits `pyproject.toml` and `uv.lock`):

```bash
for d in shared relay netbridge-agent socks-proxy socks-proxy-win e2e; do (cd "$d" && uv add --group dev "pytest-cov>=7.1.0"); done
```

Verify each lock resolved `coverage` 7.16.2: `grep -A1 'name = "coverage"' */uv.lock`.

- [ ] **Step 3: Add coverage config with a placeholder floor of 0**

Append to each `pyproject.toml` (replace `<pkg>`: `shared_auth`, `relay`, `netbridge_agent`, `socks_proxy`, `socks_proxy_win`, `netbridge_e2e`):

```toml
[tool.coverage.run]
branch = true
source = ["src/<pkg>"]

[tool.coverage.report]
fail_under = 0
precision = 2
show_missing = true
skip_covered = true
```

Note: `netbridge-agent`, `socks-proxy-win` and `e2e` have a duplicated `[tool.pytest.ini_options]` header line (two identical lines). Leave pytest config as-is in this task except: if the duplicate header makes TOML invalid for `tomllib`, collapse it to one line. Check with `uv run --no-project python -c "import tomllib,sys;tomllib.load(open(sys.argv[1],'rb'))" <comp>/pyproject.toml` for each component.

- [ ] **Step 4: Measure the baseline**

```bash
for d in shared relay netbridge-agent socks-proxy socks-proxy-win e2e; do echo "== $d"; (cd "$d" && uv run pytest -q --cov --cov-report=term 2>&1 | grep -E '^TOTAL|passed|failed'); done
```

Expected (approximate, 2026-10-03): shared 71, relay 47, netbridge-agent 36, socks-proxy 46, socks-proxy-win 34, e2e 57. All tests pass. Record the exact two-decimal totals.

- [ ] **Step 5: Set each floor to floor(measured)**

Set `fail_under` in each component to the integer part of its measured total (e.g. 46.83 → 46).

- [ ] **Step 6: Verify the floor bites**

For one component (relay), temporarily set `fail_under` to measured+1 and run `cd relay && uv run pytest -q --cov`.
Expected: exit code non-zero and `FAIL Required test coverage of <N>% not reached. Total coverage: <X>%` with X shown to 2 decimals. Restore the real floor. Also run plain `uv run pytest -q` and confirm no coverage output (not measured).

- [ ] **Step 7: Ignore coverage outputs**

Add to the root `.gitignore` (check existing entries first):

```
.coverage
.coverage.*
coverage.xml
htmlcov/
junit.xml
diff-cover.html
diff-cover.md
```

- [ ] **Step 8: Commit**

```bash
git add .gitignore socks-proxy-win/tests/conftest.py */pyproject.toml */uv.lock
git commit -m "Measure coverage in every component with a per-component floor"
```

---

### Task 2: Block non-loopback connects in unit tests

**Files:**
- Modify: `shared/pyproject.toml`, `relay/pyproject.toml`, `netbridge-agent/pyproject.toml`, `socks-proxy/pyproject.toml`, `socks-proxy-win/pyproject.toml` (+ their `uv.lock`)
- Create: `shared/tests/test_network_guard.py`, `relay/tests/test_network_guard.py`, `netbridge-agent/tests/test_network_guard.py`, `socks-proxy/tests/test_network_guard.py`, `socks-proxy-win/tests/test_network_guard.py` (identical content)
- Modify: any test that now fails because it opened a real non-loopback connection

**Interfaces:**
- Consumes: Task 1 pyproject layout.
- Produces: in the five product components, `socket.connect` to a non-loopback host raises `pytest_socket.SocketConnectBlockedError`.

- [ ] **Step 1: Write the guard test (in all five components)**

`<comp>/tests/test_network_guard.py`:

```python
import socket

import pytest
from pytest_socket import SocketConnectBlockedError


def test_non_loopback_connect_is_blocked():
    with socket.socket() as s, pytest.raises(SocketConnectBlockedError):
        s.connect(("192.0.2.1", 80))  # TEST-NET-1: never routable


def test_loopback_connect_still_works():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        with socket.create_connection(server.getsockname(), timeout=5):
            pass
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd relay && uv run pytest tests/test_network_guard.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'pytest_socket'`.

- [ ] **Step 3: Add pytest-socket and the addopts**

```bash
for d in shared relay netbridge-agent socks-proxy socks-proxy-win; do (cd "$d" && uv add --group dev "pytest-socket>=0.8.1"); done
```

In each of the five `pyproject.toml`, ensure a single `[tool.pytest.ini_options]` table containing (keep existing keys such as `testpaths`, `asyncio_mode`):

```toml
[tool.pytest.ini_options]
addopts = "--allow-hosts=127.0.0.1,::1,localhost"
```

`shared`, `relay` and `socks-proxy` have no pytest table yet — create it. Collapse any duplicated header line.

- [ ] **Step 4: Run the guard test**

Run: `cd relay && uv run pytest tests/test_network_guard.py -q`
Expected: `2 passed`. If `test_non_loopback_connect_is_blocked` fails because the error class differs in 0.8.1, inspect `uv run python -c "import pytest_socket; print(dir(pytest_socket))"` and use the class the plugin raises for host-restricted connects; do not weaken the assertion to `Exception`.

- [ ] **Step 5: Run every product suite and fix breakages**

```bash
for d in shared relay netbridge-agent socks-proxy socks-proxy-win; do echo "== $d"; (cd "$d" && uv run pytest -q 2>&1 | tail -3); done
```

For each failure caused by `SocketConnectBlockedError`: the test was reaching a real host. Replace that with a monkeypatched/fake transport or a local server bound to `127.0.0.1`. Only when the test's purpose genuinely requires a non-loopback socket (e.g. it asserts on a connect error to an unroutable address), mark it `@pytest.mark.enable_socket` with a one-line comment why. Expected end state: same pass counts as before plus 2 per component.

- [ ] **Step 6: Re-check floors**

Run Task 1 Step 4's loop. Coverage must not drop below the floors set in Task 1 (fixes replace real I/O with fakes, so totals may shift slightly). If a total moved below its floor, the fix lost coverage — restore it rather than lowering the floor.

- [ ] **Step 7: Commit**

```bash
git add */pyproject.toml */uv.lock */tests/test_network_guard.py <any fixed test files>
git commit -m "Block non-loopback connects in unit tests"
```

---

### Task 3: `scripts/coverage_report.py` — combine and summarise

**Files:**
- Create: `scripts/coverage_report.py`
- Create: `scripts/tests/test_coverage_report.py`

**Interfaces:**
- Consumes: `<component>/.coverage` data files and `<component>/pyproject.toml` `[tool.coverage.report] fail_under` (Task 1).
- Produces: CLI `uv run --no-project --with coverage==7.16.2 python scripts/coverage_report.py [--root DIR]` writing `<root>/.coverage.combined`, `<root>/coverage.xml` (repo-relative filenames), `<root>/htmlcov/`, a markdown table on stdout and appended to `$GITHUB_STEP_SUMMARY` when set. Exit 0 unless no data at all or combine/xml/html fails.
- Python API (for tests): `COMPONENTS: tuple[str, ...]`, `read_floor(comp_dir: Path) -> float | None`, `component_total(comp_dir: Path) -> float`, `make_row(comp: str, pct: float | None, floor: float | None) -> dict`, `render(rows: list[dict]) -> str`, `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Write the failing tests**

`scripts/tests/test_coverage_report.py`:

```python
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "coverage_report.py"
spec = importlib.util.spec_from_file_location("coverage_report", SCRIPT)
cr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cr)


def make_component(root: Path, name: str, floor: int | None, run_both: bool) -> Path:
    """A tiny package with real coverage data: f() always runs, g() only if run_both."""
    comp = root / name
    pkg = comp / "src" / f"pkg_{name.replace('-', '_')}"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("def f():\n    return 1\n\n\ndef g():\n    return 2\n")
    report = f"fail_under = {floor}\n" if floor is not None else ""
    (comp / "pyproject.toml").write_text(
        f'[tool.coverage.run]\nbranch = true\nsource = ["src/{pkg.name}"]\n\n'
        f"[tool.coverage.report]\n{report}precision = 2\n")
    (comp / "drive.py").write_text(
        f"import sys\nsys.path.insert(0, 'src')\nimport {pkg.name} as p\np.f()\n" + ("p.g()\n" if run_both else ""))
    # source = ["src/<pkg>"] keeps drive.py itself out of the data
    subprocess.run([sys.executable, "-m", "coverage", "run", "drive.py"], cwd=comp, check=True)
    return comp


@pytest.fixture
def root(tmp_path, monkeypatch):
    monkeypatch.setattr(cr, "COMPONENTS", ("alpha", "beta", "gamma"))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return tmp_path


def test_read_floor(root):
    comp = make_component(root, "alpha", 42, run_both=True)
    assert cr.read_floor(comp) == 42
    comp2 = make_component(root, "beta", None, run_both=True)
    assert cr.read_floor(comp2) is None


def test_component_total(root):
    assert cr.component_total(make_component(root, "alpha", 0, run_both=True)) == 100.0
    assert 0 < cr.component_total(make_component(root, "beta", 0, run_both=False)) < 100


def test_below_floor_still_reports_total(root):
    comp = make_component(root, "alpha", 99, run_both=False)  # coverage report exits 2 here
    assert 0 < cr.component_total(comp) < 99


def test_make_row_statuses():
    assert cr.make_row("x", 50.0, 40)["status"] == "ok"
    assert cr.make_row("x", 39.99, 40)["status"] == "below floor"
    assert cr.make_row("x", None, 40)["status"] == "no data"
    assert cr.make_row("x", 50.0, None)["status"] == "no floor"


def test_hint_uses_two_decimals():
    assert cr.make_row("x", 46.99, 40)["hint"] == "raise fail_under to 46"
    assert cr.make_row("x", 40.5, 40)["hint"] == ""
    assert cr.make_row("x", 39.99, 40)["hint"] == ""


def test_render_is_markdown_table():
    out = cr.render([cr.make_row("relay", 47.25, 47)])
    assert "| Component | Coverage | Floor | Status | Hint |" in out
    assert "| relay | 47.25% | 47 | ok |" in out


def test_main_combines_to_repo_relative_xml(root):
    make_component(root, "alpha", 0, run_both=True)
    make_component(root, "beta", 0, run_both=False)
    assert cr.main(["--root", str(root)]) == 0
    xml = (root / "coverage.xml").read_text()
    assert 'filename="alpha/src/pkg_alpha/__init__.py"' in xml
    assert 'filename="beta/src/pkg_beta/__init__.py"' in xml
    assert (root / "htmlcov" / "index.html").exists()


def test_main_missing_component_is_no_data_not_error(root, capsys):
    make_component(root, "alpha", 0, run_both=True)
    assert cr.main(["--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "| gamma | — | — | no data |" in out


def test_main_appends_to_step_summary(root, monkeypatch):
    make_component(root, "alpha", 0, run_both=True)
    summary = root / "summary.md"
    summary.write_text("before\n")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    cr.main(["--root", str(root)])
    text = summary.read_text()
    assert text.startswith("before\n") and "| alpha |" in text


def test_main_without_any_data_fails(root):
    assert cr.main(["--root", str(root)]) != 0


def test_main_fails_when_combine_fails(root, monkeypatch):
    make_component(root, "alpha", 0, run_both=True)
    real = cr.run_coverage

    def broken(args, cwd):
        if args[0] == "combine":
            raise subprocess.CalledProcessError(1, args)
        return real(args, cwd)

    monkeypatch.setattr(cr, "run_coverage", broken)
    assert cr.main(["--root", str(root)]) != 0
```

- [ ] **Step 2: Run to verify they fail**

Run: `uv run --no-project --with pytest --with coverage==7.16.2 pytest scripts/tests -q`
Expected: FAIL — `FileNotFoundError` for `scripts/coverage_report.py`.

- [ ] **Step 3: Implement**

`scripts/coverage_report.py`:

```python
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
        raise RuntimeError(f"coverage report in {comp_dir} failed: {r.stderr.strip()}")
    return float(r.stdout.strip())


def make_row(comp: str, pct: float | None, floor: float | None) -> dict:
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
        if data.exists():
            data_files.append(str(data))
            rows.append(make_row(comp, component_total(comp_dir), floor))
        else:
            rows.append(make_row(comp, None, floor))

    table = render(rows)
    print(table)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(table)

    if not data_files:
        print("no component produced coverage data", file=sys.stderr)
        return 1
    # data files hold absolute paths under this checkout; reporting from the root makes them repo-relative
    steps = (["combine", "--keep", f"--data-file={COMBINED}", *data_files],
             ["xml", f"--data-file={COMBINED}", "-o", "coverage.xml"],
             ["html", f"--data-file={COMBINED}", "-d", "htmlcov"])
    for args in steps:
        try:
            r = run_coverage(args, root)
        except subprocess.CalledProcessError as e:
            print(f"coverage {args[0]} failed: {e}", file=sys.stderr)
            return 1
        if r.returncode not in (0, 2):
            print(f"coverage {args[0]} failed: {r.stderr.strip()}", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Note: `coverage xml`/`html` run from a root with no coverage config, so they never apply a `fail_under` (exit 2 is still tolerated defensively).

- [ ] **Step 4: Run tests**

Run: `uv run --no-project --with pytest --with coverage==7.16.2 pytest scripts/tests -q`
Expected: all pass.

- [ ] **Step 5: Try it on the real repo**

```bash
for d in shared relay; do (cd "$d" && uv run pytest -q --cov --cov-report=); done
uv run --no-project --with coverage==7.16.2 python scripts/coverage_report.py
grep -o 'filename="[^"]*"' coverage.xml | head -3
```

Expected: table with shared/relay rows and "no data" for the others; filenames like `relay/src/relay/__main__.py`. Delete generated files afterwards (`rm -rf .coverage.combined coverage.xml htmlcov */.coverage`).

- [ ] **Step 6: Commit**

```bash
git add scripts/coverage_report.py scripts/tests/test_coverage_report.py
git commit -m "Add a script that combines component coverage into one report"
```

---

### Task 4: CI gate in `ci.yml` + local `scripts/coverage.sh`

**Files:**
- Modify: `.github/workflows/ci.yml` (`test` job, workflow-level `concurrency`)
- Create: `scripts/coverage.sh` (executable)
- Modify: `README.md` (Development section)

**Interfaces:**
- Consumes: Task 1 `uv run pytest --cov`; Task 3 `scripts/coverage_report.py` CLI.
- Produces: CI job `test` that runs all six suites with coverage, the report, diff-cover on PRs, and uploads `coverage-and-junit`.

- [ ] **Step 1: Write `scripts/coverage.sh`**

```bash
#!/usr/bin/env bash
# Local equivalent of the CI coverage gate: every component's tests with
# coverage (floors enforced), the combined report, then diff-cover.
#   scripts/coverage.sh [compare-branch]   (default: origin/main)
set -uo pipefail
cd "$(dirname "$0")/.."
compare="${1:-origin/main}"
status=0

for comp in shared relay netbridge-agent socks-proxy socks-proxy-win e2e; do
  echo "== $comp"
  rm -f "$comp/.coverage"
  (cd "$comp" && uv sync -q && uv run pytest -q --cov --cov-report=) || status=1
done

uv run --no-project --with coverage==7.16.2 python scripts/coverage_report.py || status=1
if [ -f coverage.xml ]; then
  uvx --from diff-cover==10.6.0 diff-cover coverage.xml --compare-branch="$compare" --fail-under=80 || status=1
fi
exit $status
```

`chmod +x scripts/coverage.sh`

- [ ] **Step 2: Run it locally**

Run: `scripts/coverage.sh`
Expected: all six components pass their floors, a table prints, diff-cover reports on the branch's changed lines (product files changed so far are only tests/config, so likely "No lines with coverage information in this diff"), exit 0. Clean generated files afterwards.

- [ ] **Step 3: Rewrite the `test` job in `ci.yml`**

Add at workflow level (after `on:`):

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: ${{ github.event_name == 'pull_request' }}
```

Replace the `test` job with:

```yaml
  test:
    runs-on: ubuntu-latest

    env:
      NETBRIDGE_ALLOWED_TENANTS: "11111111-1111-1111-1111-111111111111"

    steps:
      - uses: actions/checkout@v7
        with:
          fetch-depth: 0  # diff-cover compares against the base branch

      - uses: actions/setup-python@v7
        with:
          python-version: "3.14"

      - uses: astral-sh/setup-uv@v7

      - name: Install system dependencies for socks-proxy tray
        run: sudo apt-get update && sudo apt-get install -y libgirepository-2.0-dev libcairo2-dev

      - name: Test shared
        if: ${{ !cancelled() }}
        working-directory: shared
        run: uv sync && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test relay
        if: ${{ !cancelled() }}
        working-directory: relay
        run: uv sync && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test socks-proxy
        if: ${{ !cancelled() }}
        working-directory: socks-proxy
        run: uv sync && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test socks-proxy-win
        if: ${{ !cancelled() }}
        working-directory: socks-proxy-win
        run: uv sync && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test agent
        if: ${{ !cancelled() }}
        working-directory: netbridge-agent
        run: uv sync --group dev && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test the E2E driver
        if: ${{ !cancelled() }}
        working-directory: e2e
        run: uv sync && uv run pytest --cov --cov-report=xml --junitxml=junit.xml

      - name: Test the CI scripts
        if: ${{ !cancelled() }}
        run: uv run --no-project --with pytest --with coverage==7.16.2 pytest scripts/tests -q

      - name: Coverage report
        if: ${{ !cancelled() }}
        run: uv run --no-project --with coverage==7.16.2 python scripts/coverage_report.py

      - name: Diff coverage (new and changed lines >= 80%)
        if: ${{ !cancelled() && github.event_name == 'pull_request' && hashFiles('coverage.xml') != '' }}
        run: >
          uvx --from diff-cover==10.6.0 diff-cover coverage.xml
          --compare-branch=origin/${{ github.base_ref }} --fail-under=80
          --html-report diff-cover.html --markdown-report diff-cover.md

      - name: Diff coverage summary
        if: ${{ always() && hashFiles('diff-cover.md') != '' }}
        run: cat diff-cover.md >> "$GITHUB_STEP_SUMMARY"

      - uses: actions/upload-artifact@v7
        if: always()
        with:
          name: coverage-and-junit
          path: |
            */coverage.xml
            */junit.xml
            coverage.xml
            htmlcov/
            diff-cover.html
            diff-cover.md
          if-no-files-found: ignore
```

In the `e2e-source` job remove its now-duplicated "Test the E2E driver" step (the driver tests run in `test`). Keep everything else in `e2e-source` for Task 6.

- [ ] **Step 4: Validate the workflow syntax**

Run: `uvx --from check-jsonschema check-jsonschema --builtin-schema vendor.github-workflows .github/workflows/ci.yml`
Expected: `ok -- validation done`.

- [ ] **Step 5: Document**

In `README.md` "Development", after the "Run tests" block add:

```markdown
# Run tests with coverage (enforces the component's fail_under floor)
uv run --native-tls pytest --cov
```

and below the code block:

```markdown
Every component has a coverage floor (`[tool.coverage.report] fail_under` in its
`pyproject.toml`). CI fails if a component drops below its floor or if a pull
request's new and changed lines under `*/src/` are less than 80% covered
(diff-cover). When the CI summary says a component can raise its floor, raise it
in the same PR. `scripts/coverage.sh` runs the same gate locally.
```

- [ ] **Step 6: Commit**

```bash
git add .github/workflows/ci.yml scripts/coverage.sh README.md
git commit -m "Gate CI on coverage floors and diff coverage, run socks-proxy-win tests"
```

---

### Task 5: E2E coverage module

**Files:**
- Create: `e2e/src/netbridge_e2e/cov.py`
- Create: `e2e/tests/test_cov.py`

**Interfaces:**
- Consumes: `stack._uv(project, *args) -> list[str]` and `stack.REPO: Path` from `e2e/src/netbridge_e2e/stack.py`.
- Produces (used by Task 6):
  - `PACKAGES: dict[str, str]` — package → repo-relative source dir: `{"relay": "relay/src/relay", "netbridge_agent": "netbridge-agent/src/netbridge_agent", "socks_proxy": "socks-proxy/src/socks_proxy", "shared_auth": "shared/src/shared_auth"}`
  - `class E2ECoverage(dir: Path, repo: Path = REPO)` with:
    - `prepare() -> None` — mkdir, delete only `.coverage` / `.coverage.*` in dir, write `dir/coveragerc`
    - `rcfile: Path` attribute
    - `wrap(project: str, module_args: list[str]) -> list[str] | None` — `[<venv python>, "-m", "coverage", "run", "--rcfile=<rcfile>", *module_args]`; returns `None` (and records a warning) if the interpreter cannot be resolved, so the caller falls back to its uninstrumented argv
    - `warn(msg: str) -> None` — record a warning
    - `finalize() -> dict` — never raises; returns `{"total": float | None, "packages": {pkg: float | None}, "warnings": [str]}` and writes `dir/summary.md`

- [ ] **Step 1: Write the failing tests**

`e2e/tests/test_cov.py`:

```python
import subprocess
import sys
from pathlib import Path

import pytest

from netbridge_e2e import cov


@pytest.fixture
def fake_repo(tmp_path):
    """A repo layout with the four packages, each one function long."""
    repo = tmp_path / "repo"
    for rel in cov.PACKAGES.values():
        pkg = repo / rel
        pkg.mkdir(parents=True)
        (pkg / "__init__.py").write_text("def f():\n    return 1\n")
    return repo


@pytest.fixture
def c(tmp_path, fake_repo, monkeypatch):
    e = cov.E2ECoverage(tmp_path / "cov", repo=fake_repo)
    monkeypatch.setattr(e, "_python", lambda project: sys.executable)  # the driver's own venv has coverage
    return e


def test_prepare_removes_only_data_files(c):
    c.dir.mkdir(parents=True)
    for name in (".coverage", ".coverage.host.1.x", ".coveragerc-old", "summary.md", "keep.txt"):
        (c.dir / name).write_text("stale")
    c.prepare()
    left = sorted(p.name for p in c.dir.iterdir())
    assert left == [".coveragerc-old", "coveragerc", "keep.txt", "summary.md"]


def test_rcfile_content(c, fake_repo):
    c.prepare()
    text = c.rcfile.read_text()
    for line in ("branch = true", "parallel = true", "sigterm = true",
                 "source_pkgs = relay, netbridge_agent, socks_proxy, shared_auth",
                 f"data_file = {c.dir / '.coverage'}"):
        assert line in text


def test_rcfile_maps_site_packages_shared_auth(c, fake_repo):
    c.prepare()
    text = c.rcfile.read_text()
    assert f"shared_auth =\n    {fake_repo / 'shared/src/shared_auth'}\n    */site-packages/shared_auth" in text


def test_wrap(c):
    c.prepare()
    argv = c.wrap("relay", ["-m", "relay", "--no-auth"])
    assert argv == [sys.executable, "-m", "coverage", "run", f"--rcfile={c.rcfile}", "-m", "relay", "--no-auth"]


def test_wrap_failure_returns_none_and_warns(c, monkeypatch):
    c.prepare()

    def broken(project):
        raise subprocess.CalledProcessError(1, ["uv"])

    monkeypatch.setattr(c, "_python", broken)
    assert c.wrap("relay", ["-m", "relay"]) is None
    assert any("relay" in w and "not instrumented" in w for w in c.warnings)


def test_python_resolves_the_component_venv(tmp_path, monkeypatch):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, stdout="/x/relay/.venv/bin/python\n", stderr="")

    monkeypatch.setattr(cov.subprocess, "run", fake_run)
    e = cov.E2ECoverage(tmp_path)
    assert e._python("relay") == "/x/relay/.venv/bin/python"
    assert e._python("relay") == "/x/relay/.venv/bin/python"
    assert len(calls) == 1  # cached per project
    assert calls[0][:4] == ["uv", "run", "--project", str(cov.REPO / "relay")]


def drive(c, src_root: Path, pkg: str):
    (src_root / f"drive_{pkg}.py").write_text(f"import {pkg}\n{pkg}.f()\n")
    subprocess.run([sys.executable, "-m", "coverage", "run", f"--rcfile={c.rcfile}", f"drive_{pkg}.py"],
                   cwd=src_root, check=True)


def test_finalize_per_package(c, fake_repo):
    c.prepare()
    drive(c, (fake_repo / cov.PACKAGES["relay"]).parent, "relay")
    result = c.finalize()
    assert result["packages"]["relay"] == 100.0
    assert result["total"] is not None
    md = (c.dir / "summary.md").read_text()
    assert "| relay | 100.00% |" in md


def test_finalize_warns_for_packages_without_data(c, fake_repo):
    c.prepare()
    drive(c, (fake_repo / cov.PACKAGES["relay"]).parent, "relay")
    result = c.finalize()
    assert result["packages"]["socks_proxy"] is None
    assert any("socks_proxy" in w for w in result["warnings"])


def test_finalize_maps_site_packages_copy(c, fake_repo, tmp_path):
    c.prepare()
    site = tmp_path / "venv" / "lib" / "site-packages"
    (site / "shared_auth").mkdir(parents=True)
    (site / "shared_auth" / "__init__.py").write_text("def f():\n    return 1\n")
    drive(c, site, "shared_auth")
    assert c.finalize()["packages"]["shared_auth"] == 100.0


def test_finalize_never_raises(c):
    c.prepare()  # no data at all
    result = c.finalize()
    assert result["total"] is None
    assert result["warnings"]


def test_warn_is_reported(c):
    c.prepare()
    c.warn("relay from image: not instrumented")
    assert "relay from image: not instrumented" in c.finalize()["warnings"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd e2e && uv run pytest tests/test_cov.py -q`
Expected: FAIL — `ImportError: cannot import name 'cov'`.

- [ ] **Step 3: Implement**

`e2e/src/netbridge_e2e/cov.py`:

```python
"""Report-only coverage of the source-mode journey (--coverage DIR).

Each component runs under `coverage run` with its own venv interpreter: through
`uv run` the direct child would be uv, and Proc.stop SIGKILLs the group right
after uv exits — before Python's atexit flush.
"""
import json
import subprocess
import sys
from pathlib import Path

from .stack import REPO, _uv

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
        for f in [self.dir / ".coverage", *self.dir.glob(".coverage.*")]:  # a reused dir must not count an earlier run
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
            out = subprocess.run(_uv(project, "python", "-c", "import sys; print(sys.executable)"),
                                 capture_output=True, text=True, check=True, timeout=600)
            self._pythons[project] = out.stdout.strip()
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
        self._write_markdown(result)
        return result

    def _coverage(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-m", "coverage", *args, f"--rcfile={self.rcfile}"],
                              cwd=self.repo, capture_output=True, text=True, timeout=300)

    def _combine_into(self, result: dict) -> None:
        if not list(self.dir.glob(".coverage.*")):
            raise RuntimeError("no data files (did any component start under coverage?)")
        for args in (("combine", "--keep"), ("json", "-o", str(self.dir / "coverage.json")),
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
```

Notes for the implementer:
- `finalize()` uses the driver's own interpreter (`sys.executable`, the `e2e` venv), which has coverage via the dev group from Task 1. The data format is compatible across coverage 7.x.
- `--rcfile` goes after the subcommand args; `coverage` accepts options anywhere after the subcommand.
- If `test_finalize_maps_site_packages_copy` fails because the remap needs the fake site dir to match `*/site-packages/shared_auth`, check the path you created ends in `site-packages/shared_auth` (it does: `venv/lib/site-packages/shared_auth`).

- [ ] **Step 4: Run tests**

Run: `cd e2e && uv run pytest tests/test_cov.py -q`
Expected: all pass. Then the whole driver suite: `cd e2e && uv run pytest -q` — all pass.

- [ ] **Step 5: Commit**

```bash
git add e2e/src/netbridge_e2e/cov.py e2e/tests/test_cov.py
git commit -m "Add report-only coverage collection for the e2e journey"
```

---

### Task 6: Wire `--coverage` into the journey, stack and CI

**Files:**
- Modify: `e2e/src/netbridge_e2e/stack.py` (`Relay.__init__/start`, `SourceAgent.__init__/start`, `SourceProxy.__init__/start`)
- Modify: `e2e/src/netbridge_e2e/journey.py` (`parse_args`, `Journey.__init__`, `run`, `_journey`, `_components`, `_write_summary`)
- Modify: `e2e/tests/test_stack.py`, `e2e/tests/test_journey.py`
- Modify: `.github/workflows/ci.yml` (`e2e-source` job)
- Modify: `e2e/README.md`

**Interfaces:**
- Consumes: `cov.E2ECoverage` (Task 5).
- Produces: CLI flag `--coverage DIR` (source mode only); `e2e-summary.json` gains `"coverage": {...}` when used; `DIR/summary.md`.

- [ ] **Step 1: Write failing stack tests**

Append to `e2e/tests/test_stack.py`:

```python
class FakeCov:
    def __init__(self):
        self.warnings = []

    def wrap(self, project, module_args):
        return ["COV", project, *module_args]

    def warn(self, msg):
        self.warnings.append(msg)


def captured_argv(monkeypatch):
    seen = {}

    class FakeProc:
        def __init__(self, name, argv, log_path, env=None, **kw):
            seen[name] = argv

        def start(self):
            return self

    monkeypatch.setattr(stack, "Proc", FakeProc)
    monkeypatch.setattr(stack, "port_in_use", lambda port: False)
    return seen


def test_relay_argv_under_coverage(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, cov=FakeCov()).start()
    assert seen["relay"][:4] == ["COV", "relay", "-m", "relay"]
    assert "--no-auth" in seen["relay"]


def test_relay_argv_without_coverage_is_unchanged(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.Relay(tmp_path, 1, blocked_port=2, env={}).start()
    assert seen["relay"][:3] == ["uv", "run", "--project"]


def test_relay_image_is_not_instrumented(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    monkeypatch.setattr(stack.subprocess, "run", lambda *a, **k: None)
    fake = FakeCov()
    stack.Relay(tmp_path, 1, blocked_port=2, env={}, image="img", cov=fake).start()
    assert seen["relay"][0] == "docker"
    assert fake.warnings == ["relay runs from a docker image: not instrumented"]


def test_wrap_failure_falls_back_to_uninstrumented_argv(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)

    class BrokenCov(FakeCov):
        def wrap(self, project, module_args):
            return None

    stack.Relay(tmp_path, 1, blocked_port=2, env={}, cov=BrokenCov()).start()
    stack.SourceAgent(tmp_path, "ws://x", env={}, cov=BrokenCov()).start()
    stack.SourceProxy(tmp_path, "ws://x", 1, 2, env={}, cov=BrokenCov()).start()
    assert seen["relay"][:3] == ["uv", "run", "--project"]
    assert seen["agent"][:3] == ["uv", "run", "--project"]
    assert seen["proxy"][:3] == ["uv", "run", "--project"]


def test_agent_and_proxy_argv_under_coverage(tmp_path, monkeypatch):
    seen = captured_argv(monkeypatch)
    stack.SourceAgent(tmp_path, "ws://x", env={}, cov=FakeCov()).start()
    stack.SourceProxy(tmp_path, "ws://x", 1, 2, env={}, cov=FakeCov()).start()
    assert seen["agent"] == ["COV", "netbridge-agent", "-m", "netbridge_agent", "--console"]
    assert seen["proxy"][:5] == ["COV", "socks-proxy", "-m", "socks_proxy", "serve"]
    assert "--no-tray" in seen["proxy"]
```

- [ ] **Step 2: Run to verify they fail**

Run: `cd e2e && uv run pytest tests/test_stack.py -q -k coverage`
Expected: FAIL — `TypeError: ... unexpected keyword argument 'cov'`.

- [ ] **Step 3: Implement in `stack.py`**

`Relay.__init__` gains `cov=None` (store `self._cov = cov`; warn once there if `image and cov`):

```python
    def __init__(self, logs_dir: Path, port: int, blocked_port: int, env: dict, image: str | None = None, cov=None):
        ...
        self._cov = None if image else cov
        if image and cov:
            cov.warn("relay runs from a docker image: not instrumented")
```

In `Relay.start`, replace the non-image branch:

```python
        else:
            argv = (self._cov and self._cov.wrap("relay", relay_args)) or _uv("relay", "python", *relay_args)
```

`SourceAgent.__init__(self, work, relay_url, env, cov=None)` stores `self._cov = cov`; `start`:

```python
    def start(self) -> None:
        module = ["-m", "netbridge_agent", "--console"]
        argv = (self._cov and self._cov.wrap("netbridge-agent", module)) or _uv("netbridge-agent", "python", *module)
        self.proc = Proc("agent", argv, self._stdout, env=self._env).start()
```

`SourceProxy.__init__(self, work, relay_url, socks_port, http_port, env, cov=None)`: keep the CLI args in one list and build argv in `start`:

```python
        self._serve = ["serve", "--relay", relay_url, "--host", "127.0.0.1", "--port", str(socks_port),
                       "--http-port", str(http_port), "--no-tray"]
        self._cov = cov
    ...
    def start(self) -> None:
        # python -m socks_proxy runs the same main() as the netbridge-socks entry point
        argv = ((self._cov and self._cov.wrap("socks-proxy", ["-m", "socks_proxy", *self._serve]))
                or _uv("socks-proxy", "netbridge-socks", *self._serve))
        self.proc = Proc("proxy", argv, self._stdout, env=self._env).start()
```

Check nothing else reads `SourceProxy._argv` (`grep -rn "_argv" e2e/`); update any test that did.

- [ ] **Step 4: Run stack tests**

Run: `cd e2e && uv run pytest tests/test_stack.py -q`
Expected: all pass.

- [ ] **Step 5: Write failing journey tests**

Append to `e2e/tests/test_journey.py` (follow the file's existing import style; it already imports `journey`):

```python
def test_coverage_flag_parses_in_source_mode(tmp_path):
    args = journey.parse_args(["--mode", "source", "--coverage", str(tmp_path / "cov")])
    assert args.coverage == str(tmp_path / "cov")


def test_coverage_flag_rejected_in_exe_mode(monkeypatch):
    monkeypatch.setattr(journey, "IS_WINDOWS", True)
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "exe", "--coverage", "x"])


def test_summary_includes_coverage(tmp_path, monkeypatch):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--coverage", str(tmp_path / "cov")])
    j = journey.Journey(args)
    monkeypatch.setattr(j, "_journey", lambda: None)
    monkeypatch.setattr(j.cov, "finalize", lambda: {"total": 12.5, "packages": {}, "warnings": []})
    assert j.run() == 0
    summary = json.loads((tmp_path / "e2e-summary.json").read_text())
    assert summary["coverage"]["total"] == 12.5


def test_coverage_prepare_failure_runs_uninstrumented(tmp_path, monkeypatch):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--coverage", str(tmp_path / "cov")])
    j = journey.Journey(args)

    def boom():
        raise OSError("read-only")

    monkeypatch.setattr(j.cov, "prepare", boom)
    seen = {}

    def first_step():  # the "network" step runs right after the coverage preamble
        seen["cov"] = j.cov
        raise RuntimeError("stop here")

    monkeypatch.setattr(journey.netinfo, "private_ipv4", first_step)
    j.run()
    assert seen["cov"] is None
    summary = json.loads((tmp_path / "e2e-summary.json").read_text())
    assert "coverage disabled" in summary["coverage"]["warnings"][0]


def test_coverage_failure_never_changes_exit_code(tmp_path, monkeypatch):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--coverage", str(tmp_path / "cov")])
    j = journey.Journey(args)
    monkeypatch.setattr(j, "_journey", lambda: None)

    def boom():
        raise RuntimeError("x")

    monkeypatch.setattr(j.cov, "finalize", boom)
    assert j.run() == 0
```

Add `import json` / `import pytest` at the top if missing.

- [ ] **Step 6: Run to verify they fail**

Run: `cd e2e && uv run pytest tests/test_journey.py -q -k coverage`
Expected: FAIL — `unrecognized arguments: --coverage`.

- [ ] **Step 7: Implement in `journey.py`**

- `parse_args`: add
  ```python
  p.add_argument("--coverage", metavar="DIR",
                 help="source mode: run relay, agent and proxy under coverage and report per package in DIR (report-only)")
  ```
  and after the existing `--relay-image` check:
  ```python
  if args.coverage and args.mode != "source":
      p.error("--coverage works in source mode only")
  ```
- `Journey.__init__`: `self.cov = E2ECoverage(Path(args.coverage).resolve()) if args.coverage else None` and `self.coverage: dict | None = None` (import `from .cov import E2ECoverage`).
- `_journey`: right after `logs.mkdir(...)`:
  ```python
        if self.cov:
            try:
                self.cov.prepare()
            except Exception as e:  # noqa: BLE001 — report-only: run uninstrumented
                print(f"coverage disabled: {type(e).__name__}: {e}", flush=True)
                self.coverage = {"total": None, "packages": {}, "warnings": [f"coverage disabled: {type(e).__name__}: {e}"]}
                self.cov = None
  ``` Pass `cov=self.cov` to `Relay(...)`, and in `_components` to `SourceAgent(...)` and `SourceProxy(...)`.
- `run`, inside `finally`, after the cleanup loop and before `_write_summary`:
  ```python
            if self.cov:  # processes are stopped now, so their data is flushed (None if prepare failed)
                try:
                    self.coverage = self.cov.finalize()
                except Exception as e:  # noqa: BLE001 — report-only
                    print(f"coverage: {type(e).__name__}: {e}", flush=True)
  ```
- `_write_summary`: `if self.coverage is not None: summary["coverage"] = self.coverage`, and print `E2E coverage: <total>%` (or the warnings) after the step list.

- [ ] **Step 8: Run the driver suite**

Run: `cd e2e && uv run pytest -q`
Expected: all pass.

- [ ] **Step 9: Run the real journey with coverage**

```bash
for p in relay netbridge-agent socks-proxy e2e; do (cd "$p" && uv sync -q); done
uv run --project e2e python -m netbridge_e2e --mode source --work /tmp/nb-e2e-cov --coverage /tmp/nb-e2e-cov/coverage
cat /tmp/nb-e2e-cov/coverage/summary.md
```

Expected: journey passes exactly as without `--coverage`; `summary.md` shows non-zero numbers for `relay`, `netbridge_agent`, `socks_proxy`, `shared_auth` and no "no coverage data" warnings. If a package has no data, that component did not flush on SIGTERM — investigate its shutdown (e.g. does it exit via `os._exit`, or take longer than `Proc.stop`'s 10 s?) and fix in the driver (not in product code) if possible; if it needs a product change, stop and report.

Also run the journey without `--coverage` once to confirm no regression.

- [ ] **Step 10: CI**

In `ci.yml` `e2e-source`, change the journey step to:

```yaml
      - name: E2E journey (source mode)
        run: >
          uv run --project e2e python -m netbridge_e2e --mode source
          --target-hostname netbridge-e2e-target --work "$RUNNER_TEMP/e2e"
          --coverage "$RUNNER_TEMP/e2e/coverage"

      - name: E2E coverage summary
        if: always()
        run: |
          f="$RUNNER_TEMP/e2e/coverage/summary.md"
          if [ -f "$f" ]; then cat "$f" >> "$GITHUB_STEP_SUMMARY"; fi
```

(The existing always-run artifact upload of `$RUNNER_TEMP/e2e` already includes the coverage dir.) Validate: `uvx --from check-jsonschema check-jsonschema --builtin-schema vendor.github-workflows .github/workflows/ci.yml`.

- [ ] **Step 11: Document**

In `e2e/README.md` "Run locally", add after the source-mode command:

```markdown
Add `--coverage DIR` (source mode) to run the relay, agent and proxy under
coverage: `DIR/summary.md` and the `coverage` key of `e2e-summary.json` show
which product code the journey exercised, per package. It is report-only and
never changes the result; CI's `e2e-source` job shows it in the run summary.
```

- [ ] **Step 12: Commit**

```bash
git add e2e/src/netbridge_e2e/stack.py e2e/src/netbridge_e2e/journey.py e2e/tests/test_stack.py e2e/tests/test_journey.py .github/workflows/ci.yml e2e/README.md
git commit -m "Report which product code the source-mode e2e journey covers"
```

---

## Final verification (after all tasks)

- `scripts/coverage.sh` → exit 0.
- `cd e2e && uv run pytest -q` → all pass.
- Journey with `--coverage` → passes, four packages with data.
- `git status` clean apart from ignored outputs.
