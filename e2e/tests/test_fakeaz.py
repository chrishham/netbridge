import json
import shutil
import subprocess
import sys
from pathlib import Path

from shared_auth.token import check_token_expiration

from netbridge_e2e import fakeaz

AZ_NAME = "az.cmd" if sys.platform == "win32" else "az"


def run_az(env, *args):
    az = shutil.which(AZ_NAME, path=env["PATH"])
    return subprocess.run([az, *args], env=env, capture_output=True, text=True, timeout=30)


def test_fake_az_shadows_a_real_az_on_path(tmp_path):
    real = tmp_path / "real-bin"
    real.mkdir()
    (real / AZ_NAME).write_text("echo real")
    (real / AZ_NAME).chmod(0o755)
    env = fakeaz.env_with_fake_az({"PATH": str(real)}, sys.executable, tmp_path / "calls.log")
    resolved = Path(shutil.which(AZ_NAME, path=env["PATH"])).resolve()
    assert resolved.parent == fakeaz.FAKE_AZ_DIR


def test_account_show_returns_a_user(tmp_path):
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "show")
    assert out.returncode == 0, out.stderr
    data = json.loads(out.stdout)
    assert data["user"]["name"]
    assert data["tenantId"]


def test_token_is_accepted_by_the_real_expiry_check(tmp_path):
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, tmp_path / "calls.log")
    out = run_az(env, "account", "get-access-token", "--resource", "https://management.azure.com/")
    assert out.returncode == 0, out.stderr
    token = json.loads(out.stdout)["accessToken"]
    ok, message = check_token_expiration(token)
    assert ok, message
    assert fakeaz.token_seconds_left(token) > 3000


def test_calls_are_logged_and_unknown_commands_fail(tmp_path):
    log = tmp_path / "calls.log"
    env = fakeaz.env_with_fake_az({"PATH": ""}, sys.executable, log)
    run_az(env, "account", "show")
    bad = run_az(env, "login")
    assert bad.returncode == 2
    assert log.read_text().splitlines() == ["account show", "login"]
