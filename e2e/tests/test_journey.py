import json

import pytest

from netbridge_e2e import journey


def make(tmp_path, body):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path)])

    class J(journey.Journey):
        def _journey(self):
            body(self)

    return J(args)


def test_first_failure_stops_runs_cleanups_in_reverse_and_writes_summary(tmp_path):
    order = []

    def body(j):
        j.cleanups.append(lambda: order.append("first"))
        j.cleanups.append(lambda: order.append("second"))
        j.step("ok_step", True, "fine")
        j.step("bad_step", False, "broken")
        j.step("never", True)

    j = make(tmp_path, body)
    assert j.run() == 1
    assert order == ["second", "first"]
    summary = json.loads((tmp_path / "e2e-summary.json").read_text())
    assert summary["ok"] is False and summary["mode"] == "source"
    assert [s["step"] for s in summary["steps"]] == ["ok_step", "bad_step"]


def test_check_turns_exceptions_into_failures(tmp_path):
    def body(j):
        j.check("raises", lambda: (_ for _ in ()).throw(TimeoutError("hung")))

    j = make(tmp_path, body)
    assert j.run() == 1
    assert j.results[-1] == {"step": "raises", "ok": False, "detail": "TimeoutError: hung"}


def test_unexpected_driver_error_is_reported(tmp_path):
    def body(j):
        raise RuntimeError("boom")

    j = make(tmp_path, body)
    assert j.run() == 1
    assert j.results[-1]["step"] == "driver_error"
    assert "boom" in j.results[-1]["detail"]


def test_cleanup_errors_do_not_mask_success(tmp_path):
    def body(j):
        j.cleanups.append(lambda: 1 / 0)
        j.step("only", True)

    assert make(tmp_path, body).run() == 0


def test_exe_mode_requires_both_exes(tmp_path):
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "exe", "--work", str(tmp_path)])


def test_relay_image_is_source_mode_only(tmp_path):
    args = journey.parse_args(["--mode", "source", "--work", str(tmp_path), "--relay-image", "img:tag"])
    assert args.relay_image == "img:tag"
    with pytest.raises(SystemExit):
        journey.parse_args(["--mode", "exe", "--work", str(tmp_path), "--relay-image", "img:tag"])


def test_install_failure_becomes_named_step(tmp_path):
    """Install raising RuntimeError surfaces as install_* step, not driver_error."""

    class BadAgent:
        name = "agent"

        def install(self):
            raise RuntimeError("existing installation")

        def cleanup(self):
            pass

    class GoodProxy:
        name = "proxy"

        def install(self):
            return "ok"

        def cleanup(self):
            pass

    def body(j):
        agent, proxy = BadAgent(), GoodProxy()
        for comp in (agent, proxy):
            j.cleanups.append(comp.cleanup)
        j.check("install_agent", lambda: (True, agent.install()))
        j.check("install_proxy", lambda: (True, proxy.install()))

    j = make(tmp_path, body)
    assert j.run() == 1
    assert j.results[-1]["step"] == "install_agent"
    assert "RuntimeError: existing installation" in j.results[-1]["detail"]
