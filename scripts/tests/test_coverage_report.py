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
            return subprocess.CompletedProcess(args, 1, "", "boom")
        return real(args, cwd)

    monkeypatch.setattr(cr, "run_coverage", broken)
    assert cr.main(["--root", str(root)]) != 0


def test_main_fails_when_a_step_exits_2(root, monkeypatch, capsys):
    make_component(root, "alpha", 0, run_both=True)
    real = cr.run_coverage

    def two(args, cwd):
        if args[0] == "xml":
            return subprocess.CompletedProcess(args, 2, "", "")
        return real(args, cwd)

    monkeypatch.setattr(cr, "run_coverage", two)
    assert cr.main(["--root", str(root)]) != 0
    assert "coverage xml failed" in capsys.readouterr().err


def test_main_reports_a_corrupt_component_and_combines_the_rest(root, monkeypatch, capsys):
    alpha = make_component(root, "alpha", 0, run_both=True)
    make_component(root, "beta", 0, run_both=True)
    (alpha / ".coverage").write_bytes(b"garbage, not sqlite")
    combined = []
    real = cr.run_coverage

    def spy(args, cwd):
        if args[0] == "combine":
            combined.extend(args)
        return real(args, cwd)

    monkeypatch.setattr(cr, "run_coverage", spy)
    assert cr.main(["--root", str(root)]) == 0
    out = capsys.readouterr().out
    assert "| alpha | — | 0 | error |" in out
    assert "| beta | 100.00% | 0 | ok |" in out
    assert not any("alpha" in a for a in combined)
    assert 'filename="beta/src/pkg_beta/__init__.py"' in (root / "coverage.xml").read_text()
