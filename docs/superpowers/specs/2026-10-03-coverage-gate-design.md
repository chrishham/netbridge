# Coverage baseline + gate (sub-project A)

Date: 2026-10-03
Status: approved in brainstorming (gate policy: ratchet + diff-cover)

## Context

The repo has ~715 pytest tests across five components and an e2e driver, but
no coverage measurement anywhere, no gate, and `socks-proxy-win` tests are
not run by any workflow (they also fail to collect on Linux: `pystray` picks
the AppIndicator backend and needs Gtk).

This is sub-project **A** of a four-part effort to strengthen testing:

| # | Sub-project | Status |
|---|---|---|
| A | Coverage baseline + gate (this spec) | this document |
| B | Fault/reconnect e2e (fault-injecting proxy, agent kill, heartbeat timeout, in-flight streams) | later |
| C | Auth/security e2e (auth-on journey, token matrix, pentest suite in CI) | later |
| D | Error paths + plugins in e2e, unit tests for untested modules | later |

A comes first because it gives B–D a measurable target.

Ideas borrowed from `claude-code-sandbox`: coverage with lcov/xml artifacts
uploaded `if: always()`, path to "no network in unit tests", and — fixing that
repo's weakness — an actual enforced gate instead of report-only coverage.

### Measured baseline (2026-10-03, line+branch, `--cov=src`)

| Component | Tests | Coverage |
|---|---|---|
| shared | 82 | 71% |
| relay | 64 | 47% |
| netbridge-agent | 276 (+3 skipped) | 36% |
| socks-proxy | 187 | 46% |
| socks-proxy-win | 103 (with `PYSTRAY_BACKEND=dummy`) | 34% |
| e2e driver | 35 (+3 skipped) | 57% |

## Goals

1. Every component measures line+branch coverage with the same tooling.
2. A per-component floor (`fail_under`) that cannot silently drop (ratchet).
3. New/changed lines in a PR within the six measured `src/<package>` trees
   must be ≥80% covered (diff-cover). Python outside those trees (e.g.
   `scripts/`, tests) is not in the coverage XML and therefore not gated.
4. `socks-proxy-win` tests run in CI.
5. Unit tests cannot open TCP connections to non-loopback hosts (best-effort
   guard, not a full network sandbox: DNS lookups and unconnected UDP
   `sendto` are not intercepted).
6. The source-mode e2e journey reports which product lines it exercises
   (report-only), as the yardstick for B–D.
7. Test/coverage artifacts are always uploaded, even on failure.

## Non-goals

- Writing new tests for untested modules (sub-project D).
- Coverage of the Windows exe-mode journey or the docker-image relay.
- Gating on e2e coverage.
- Lint/type-check (ruff/mypy) — separate concern.
- Changing release workflows (gaps noted under "Follow-ups").

## Design

### 1. Per-component configuration

Each of `shared`, `relay`, `netbridge-agent`, `socks-proxy`,
`socks-proxy-win`, `e2e`:

- `pytest-cov` added to the `dev` dependency group (brings `coverage`).
- `pyproject.toml` gets:

  ```toml
  [tool.coverage.run]
  branch = true
  source = ["src/<package>"]

  [tool.coverage.report]
  fail_under = <floor(baseline)>
  precision = 2
  show_missing = true
  skip_covered = true
  ```

- `precision = 2` matters: coverage compares `fail_under` against the total
  rounded to `precision` (default 0), so without it 46.6% would round to 47
  and pass a floor of 47. With two decimals the integer floor is compared
  against the real value.
- No `omit` beyond what is genuinely not product code (none expected; the
  relay's 1119-line `__main__.py` is real code and stays in).
- `--cov` is **not** added to `addopts`. Plain `uv run pytest` stays fast and
  never fails on coverage when running a subset. Coverage (and the
  `fail_under` check, which pytest-cov reads from `[tool.coverage.report]`)
  runs with `uv run pytest --cov`, which is what CI and `scripts/coverage.sh`
  do. Rationale: a floor enforced on `pytest tests/test_x.py` would fail every
  focused local run.

### 2. `socks-proxy-win` on Linux

Add `socks-proxy-win/tests/conftest.py` that sets
`os.environ.setdefault("PYSTRAY_BACKEND", "dummy")` before any test module
imports `pystray`. Verified: all 103 tests pass with it. On Windows the env var
is also honoured (the dummy backend never draws), so the suite stays
platform-neutral.

### 3. No network in unit tests

Add `pytest-socket` to the dev group of the five product components (not the
e2e driver, which is an integration harness that talks to real local
processes and runs on Windows) and add to their pytest options:

```toml
addopts = "--allow-hosts=127.0.0.1,::1,localhost"
```

`--allow-hosts` restricts `socket.connect` to loopback, so aiohttp test
servers, asyncio socketpairs and fake local servers keep working while any
connect to a real host fails with `SocketBlockedError`. (`--disable-socket` is
deliberately not used: it would block the local test servers too.) Unix
sockets are unaffected. Any test that breaks is fixed with a fake/monkeypatch,
not by widening the allow-list; if a test truly needs an exemption it uses the
`@pytest.mark.enable_socket` marker with a comment stating why.

### 4. CI: `ci.yml` `test` job

Keep a single `test` job (all components' installs share one runner; the
tests themselves take ~40 s total). Changes:

- Add `concurrency: {group: ci-${{ github.ref }}, cancel-in-progress: true}`
  at workflow level.
- Checkout with `fetch-depth: 0` (diff-cover needs `origin/main`).
- One step per component, now including `socks-proxy-win`, each running
  `uv run pytest --cov --cov-report=xml --junitxml=junit.xml`. Every test step
  has `if: ${{ !cancelled() }}` so a failing component does not hide the
  results of the others; the job still fails if any step failed.
- After the test steps (`if: ${{ !cancelled() }}`):
  1. `scripts/coverage_report.py` (see §6) combines the per-component
     `.coverage` data files into one repo-relative `coverage.xml`, and writes
     a per-component table plus "ratchet hints" to `$GITHUB_STEP_SUMMARY`.
  2. On `pull_request` only: `diff-cover coverage.xml
     --compare-branch=origin/${{ github.base_ref }} --fail-under=80
     --html-report diff-cover.html --markdown-report diff-cover.md`; the
     markdown is appended to the step summary.
- Upload artifact `coverage-and-junit` with `if: always()`: every
  component's `coverage.xml`, `junit.xml`, the combined `coverage.xml`, an
  `htmlcov/` of the combined data, and the diff-cover reports.

Tool versions for the report step are pinned through `uvx`
(`uvx --from 'coverage==<v>'`, `uvx --from 'diff-cover==<v>'`); the coverage
version matches the one locked in the components so data files combine.

### 5. Ratchet mechanics

- Initial `fail_under` per component = `floor(measured baseline)` at
  implementation time (re-measured, since the plan's own changes —
  conftest, socket guard — can shift numbers slightly).
- Raising the floor is a manual edit. `coverage_report.py` prints, per
  component, "now X%, floor Y% — raise `fail_under` to floor(X)" whenever
  `floor(X) > Y`. No auto-commit from CI (would need write access to main).
- Lowering a floor requires an explicit edit visible in review.

### 6. `scripts/coverage_report.py` and `scripts/coverage.sh`

`scripts/coverage_report.py` (stdlib only, run with `uv run --no-project`):

- Inputs: repo root; component list (constant in the script, same six names).
- For each component with a `<comp>/.coverage` file: read `fail_under` from
  `<comp>/pyproject.toml` (`tomllib`), compute the total percentage by
  shelling out to `coverage report --data-file=... --format=total`.
- Combine the data files explicitly (bare `coverage combine` only searches
  the current directory):
  `coverage combine --keep --data-file=.coverage.combined shared/.coverage relay/.coverage ...`
  (only the files that exist). All data files hold absolute paths under the
  same checkout, so no `[paths]` remapping is needed. Then
  `coverage xml --data-file=.coverage.combined -o coverage.xml` and
  `coverage html --data-file=.coverage.combined -d htmlcov` from repo root,
  which yields repo-relative filenames as diff-cover expects.
- Totals come from `coverage report --data-file=<comp>/.coverage
  --format=total --precision=2` so hints use the same precision as the
  floor.
- Output: markdown table (component, coverage, floor, status, hint) to stdout
  and, when `GITHUB_STEP_SUMMARY` is set, appended there.
- Exit code: coverage levels never affect it (enforcement is done by each
  component's `pytest --cov` for the floor and by diff-cover for new lines;
  the report must not duplicate those failures), and a component with no
  data file is a "no data" row, not an error. But if there is at least one
  data file and `coverage combine`, `xml` or `html` fails, the script exits
  non-zero, so a push to main cannot pass CI without the combined report.
  If no component produced data at all, it also exits non-zero.
- Missing data file for a component → row shows "no data" (e.g. its tests
  failed to collect).

`scripts/coverage.sh` — the local equivalent of CI: for each component
`uv sync` + `uv run pytest --cov --cov-report=`, then
`coverage_report.py`, then diff-cover against `origin/main` (or `$1`).
Continues through failing components and exits non-zero if any component or
diff-cover failed.

### 7. E2E coverage (report-only)

New driver option `--coverage DIR` (source mode only):

- The driver writes `DIR/coveragerc` with:

  ```ini
  [run]
  branch = true
  parallel = true
  sigterm = true
  source_pkgs = relay, netbridge_agent, socks_proxy, shared_auth
  data_file = DIR/.coverage

  [paths]
  shared_auth =
      <repo>/shared/src/shared_auth
      */site-packages/shared_auth
  (and the same canonical-first mapping for relay, netbridge_agent, socks_proxy)
  ```

  `shared_auth` is installed as a non-editable copy in each component's
  venv `site-packages`; without the `[paths]` mapping, combine would treat
  the three copies as distinct files.

- Before writing the rcfile and launching anything, the driver deletes only
  coverage data files in DIR (`DIR/.coverage` and `DIR/.coverage.*`; the
  rcfile is named `coveragerc`, without a dot, so it can never match), because work directories may be reused across runs
  and stale parallel data files would inflate totals or mask a component
  that produced no data.
- `Relay` (non-image), `SourceAgent` and `SourceProxy` launch their module
  through `<component venv python> -m coverage run --rcfile=DIR/coveragerc
  -m <module> ...` instead of `uv run ... python -m <module>` / the console
  script. For the proxy that is `-m socks_proxy serve ...` (same `main` as the
  `netbridge-socks` entry point). Without `--coverage` the argv is unchanged.
- The venv interpreter is used directly, not through `uv run`, because
  `Proc.stop` SIGTERMs the process group, waits only for the direct child
  (which would be `uv`) and then SIGKILLs the group: the Python child could be
  killed before its atexit coverage flush. With Python as the direct child,
  `Proc.stop` waits (10 s) for that exact process. The interpreter path is
  resolved once per component with
  `uv run --project <comp> python -c "import sys; print(sys.executable)"`,
  which also syncs the venv like the normal path does.
- `sigterm = true` makes coverage flush on SIGTERM for processes that keep
  the default handler; the relay, agent and proxy install their own
  graceful-shutdown handlers and flush via atexit when they exit normally.
- With `--relay-image` the relay is not instrumented; the driver logs that.
  In exe mode `--coverage` is rejected with a clear error.
- After the journey (pass or fail), the driver runs `coverage combine` and
  `coverage report` / `coverage xml` in DIR, records the total and per-package
  numbers in `e2e-summary.json` under `"coverage"`, and lists components that
  produced no data file as warnings. Coverage problems never change the
  journey's exit code.
- The driver also writes `DIR/summary.md`: a markdown table with the total
  and one row per instrumented package (`relay`, `netbridge_agent`,
  `socks_proxy`, `shared_auth`), computed from the combined data with
  `coverage json` (per-file numbers aggregated by top-level package), plus
  the warnings. The same numbers go into `e2e-summary.json`.
- `ci.yml` `e2e-source` passes `--coverage "$RUNNER_TEMP/e2e/coverage"`; the
  existing always-uploaded report artifact picks it up, and a step with
  `if: always()` appends `$RUNNER_TEMP/e2e/coverage/summary.md` (when it
  exists) to `$GITHUB_STEP_SUMMARY`. All coverage commands run by the driver
  pass `--rcfile` / `--data-file` explicitly, so they do not depend on the
  working directory.

### 8. Error handling

- A component whose tests fail to collect still yields junit output; the
  report shows "no data" for its coverage; the job fails on that step.
- diff-cover on a PR with no Python changes reports "No lines with coverage
  information in this diff" and exits 0.
- Coverage subprocess failures in e2e are warnings only.

## Testing

- `coverage_report.py`: unit tests in `scripts/tests/` (run in CI with
  `uv run --no-project --with pytest pytest scripts/tests`) using small
  synthetic coverage data generated in a temp dir; covers table/hints,
  missing data, summary-file append, exit codes (0 with partial data, non-zero on combine failure or no data at all).
- E2E driver: unit tests in `e2e/tests/` for argv wrapping (with/without
  `--coverage`, image mode, exe-mode rejection), rcfile content, and summary
  integration with a fake combine result.
- End-to-end verification: run `scripts/coverage.sh` locally and the
  source-mode journey with `--coverage`; confirm each of relay, agent, proxy
  produced data and the totals are non-zero.

## Success criteria

- `uv run pytest --cov` fails in any component whose coverage drops below
  its floor.
- A PR adding untested Python lines fails diff-cover at <80%.
- `socks-proxy-win`'s 103 tests run in `ci.yml`.
- A unit test attempting a non-loopback TCP connect fails.
- The e2e-source job summary shows per-package e2e coverage.
- Coverage/junit artifacts exist for failed runs.

## Follow-ups (out of scope, noted)

- `release-relay.yml` runs no relay unit tests; `release-socks-exe.yml` runs
  no unit tests; `release-socks.yml` runs no e2e.
- Windows-only unit tests (winauth, winproxy, installer) never run on
  Windows in CI.
