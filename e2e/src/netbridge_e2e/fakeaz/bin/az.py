"""Fake `az` for the E2E gate (see netbridge_e2e.fakeaz)."""
import base64
import json
import os
import sys
import time

ACCOUNT = {
    "name": "netbridge-e2e",
    "tenantId": "00000000-0000-0000-0000-0000000000e2",
    "user": {"name": "e2e@netbridge.test", "type": "user"},
}


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def make_token(lifetime: int = 3600) -> str:
    now = int(time.time())
    claims = {"exp": now + lifetime, "iat": now, "upn": ACCOUNT["user"]["name"], "tid": ACCOUNT["tenantId"]}
    return f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(claims)}.e2e"


def main(argv: list[str]) -> int:
    log = os.environ.get("NETBRIDGE_E2E_AZ_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(" ".join(argv) + "\n")
    if argv[:2] == ["account", "show"]:
        print(json.dumps(ACCOUNT))
        return 0
    if argv[:2] == ["account", "get-access-token"]:
        print(json.dumps({"accessToken": make_token(), "tokenType": "Bearer"}))
        return 0
    print(f"fake az: unsupported command: {' '.join(argv)}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
