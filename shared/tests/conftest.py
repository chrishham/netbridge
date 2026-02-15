"""Shared test configuration."""

import os

# Set NETBRIDGE_ALLOWED_TENANTS before any test modules import shared_auth.validate.
# conftest.py is loaded before test modules, so this ensures the env var is
# available at import time when _load_allowed_tenants() runs.
os.environ.setdefault(
    "NETBRIDGE_ALLOWED_TENANTS",
    "11111111-1111-1111-1111-111111111111",
)
