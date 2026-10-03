import json
import sys

import pytest

from netbridge_agent import credstore


@pytest.fixture(autouse=True)
def tmp_app(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows plaintext branch")
def test_round_trip_and_plaintext_storage():
    assert credstore.load_proxy_credentials() is None and not credstore.has_proxy_credentials()
    credstore.save_proxy_credentials("alice", "s3cret")
    assert credstore.load_proxy_credentials() == ("alice", "s3cret")
    assert credstore.has_proxy_credentials()
    stored = json.loads(credstore.get_creds_path().read_text())
    assert stored["password_plain"] == "s3cret" and stored["scheme"] == "plain"
    credstore.clear_proxy_credentials()
    assert credstore.load_proxy_credentials() is None
    credstore.clear_proxy_credentials()                      # idempotent


@pytest.mark.parametrize("content", ["{not json", "[]", '"x"', "null", "42", '{"username": "a"}', '{"password_plain": "p"}', '{"username": "", "password_plain": "p"}'])
def test_corrupt_or_partial_files_return_none(content):
    p = credstore.get_creds_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    assert credstore.load_proxy_credentials() is None


def test_windows_fork_uses_dpapi(monkeypatch):
    monkeypatch.setattr(credstore.sys, "platform", "win32")
    monkeypatch.setattr(credstore, "_dpapi_encrypt", lambda s: b"ENC" + s.encode(), raising=False)
    monkeypatch.setattr(credstore, "_dpapi_decrypt", lambda b: b[3:].decode(), raising=False)
    credstore.save_proxy_credentials("bob", "pw")
    data = json.loads(credstore.get_creds_path().read_text())
    assert "password" not in data and "password_b64" in data
    assert credstore.load_proxy_credentials() == ("bob", "pw")
