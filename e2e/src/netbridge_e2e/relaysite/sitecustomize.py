"""E2E only: point the relay's key fetch at the local JWKS stub.

Loaded from PYTHONPATH by the e2e driver. Never part of the product: there is
deliberately no configuration seam for the key URL in shared_auth.
"""
import ipaddress
import os
import sys
from urllib.parse import urlsplit

_url = os.environ.get("NETBRIDGE_E2E_JWKS_URL")


def _loopback(host: str | None) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


if _url:
    parts = urlsplit(_url)
    tenant = parts.path.strip("/").split("/")[0]
    if not _loopback(parts.hostname):
        print(f"E2E: refusing to redirect the relay key URL to non-loopback {_url}", file=sys.stderr, flush=True)
    else:
        from shared_auth import validate

        def _stub_jwks_url(tenant_id: str) -> str:
            if tenant_id != tenant:  # a token for any other tenant must never reach a key
                raise ValueError(f"E2E key stub serves tenant {tenant} only")
            return _url

        validate._get_jwks_url = _stub_jwks_url
        print(f"E2E: relay key URL redirected to {_url}", file=sys.stderr, flush=True)
