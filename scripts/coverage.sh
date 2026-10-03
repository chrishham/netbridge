#!/usr/bin/env bash
# Local equivalent of the CI coverage gate: every component's tests with
# coverage (floors enforced), the combined report, then diff-cover.
#   scripts/coverage.sh [compare-branch]   (default: origin/main)
set -uo pipefail
cd "$(dirname "$0")/.."
compare="${1:-origin/main}"
status=0
rm -f coverage.xml .coverage.combined  # diff-cover must never run on an earlier report

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
