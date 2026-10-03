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
    assert "coverage.Coverage(config_file=" in calls[0][-2] and calls[0][-1] == str(e.rcfile)


def test_python_probe_rejects_a_broken_rcfile(tmp_path, monkeypatch):
    e = cov.E2ECoverage(tmp_path / "cov")
    e.prepare()
    e.rcfile.write_text("[run]\nbranch = notabool\n")
    # the driver's own venv stands in for a component venv: same probe, real coverage
    monkeypatch.setattr(cov, "_uv", lambda project, *args: [sys.executable, *args[1:]])
    assert e.wrap("relay", ["-m", "relay"]) is None
    assert any("not instrumented" in w for w in e.warnings)


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
