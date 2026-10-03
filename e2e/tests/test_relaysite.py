import os
import subprocess
import sys

from netbridge_e2e import stack

TENANT = stack.TEST_TENANT
STUB = f"http://127.0.0.1:9/{TENANT}/discovery/v2.0/keys"
ORIGINAL = f"https://login.microsoftonline.com/{TENANT}/discovery/v2.0/keys"


def run(code, jwks_url=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "NETBRIDGE_E2E_JWKS_URL")}
    env["PYTHONPATH"] = str(stack.RELAYSITE_DIR)
    if jwks_url:
        env["NETBRIDGE_E2E_JWKS_URL"] = jwks_url
    return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=60, check=False)


def lookup(tenant):
    return f"import shared_auth.validate as v; print(v._get_jwks_url({tenant!r}))"


def test_redirects_the_stub_tenant_to_the_stub():
    r = run(lookup(TENANT), STUB)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == STUB
    assert f"E2E: relay key URL redirected to {STUB}" in r.stderr


def test_another_tenant_never_reaches_a_key():
    r = run(lookup("22222222-2222-2222-2222-222222222222"), STUB)
    assert r.returncode != 0
    assert f"ValueError: E2E key stub serves tenant {TENANT} only" in r.stderr


def test_localhost_and_ipv6_loopback_are_redirected():
    for url in (f"http://localhost:9/{TENANT}/keys", f"http://[::1]:9/{TENANT}/keys"):
        r = run(lookup(TENANT), url)
        assert r.stdout.strip() == url, r.stderr


def test_non_loopback_url_is_refused_and_leaves_the_original():
    url = f"http://10.0.0.1:9/{TENANT}/discovery/v2.0/keys"
    r = run(lookup(TENANT), url)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ORIGINAL
    assert f"E2E: refusing to redirect the relay key URL to non-loopback {url}" in r.stderr
    assert "redirected" not in r.stderr


def test_without_the_env_var_nothing_changes():
    r = run(lookup(TENANT))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ORIGINAL
    assert r.stderr == ""
