"""
Tests for shared_auth.connection module.

Covers SSL context creation with ALLOW_INSECURE guard and CA bundle support.
"""

import ssl
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _import_fresh(env_overrides: dict | None = None):
    """Import connection module with a clean environment.

    Module-level globals (VERIFY_SSL_DEFAULT, ALLOW_INSECURE, CA_BUNDLE_DEFAULT)
    are evaluated at import time, so we need to reload the module after
    patching the environment.
    """
    import importlib
    import os

    env = os.environ.copy()
    # Clear relevant vars so defaults apply unless overridden
    for key in (
        "NETBRIDGE_VERIFY_SSL",
        "NETBRIDGE_ALLOW_INSECURE",
        "NETBRIDGE_CA_BUNDLE",
    ):
        env.pop(key, None)

    if env_overrides:
        env.update(env_overrides)

    with patch.dict(os.environ, env, clear=True):
        import shared_auth.connection as mod

        importlib.reload(mod)
        return mod


# ---------------------------------------------------------------------------
# Default behaviour
# ---------------------------------------------------------------------------


class TestDefaultBehaviour:
    def test_verification_enabled_by_default(self):
        mod = _import_fresh()
        ctx = mod.create_tunnel_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_verify_true_explicit(self):
        mod = _import_fresh()
        ctx = mod.create_tunnel_ssl_context(verify=True)
        assert ctx.verify_mode == ssl.CERT_REQUIRED


# ---------------------------------------------------------------------------
# ALLOW_INSECURE guard
# ---------------------------------------------------------------------------


class TestAllowInsecureGuard:
    def test_verify_false_without_allow_insecure_keeps_verification(self):
        """verify=False alone must NOT disable verification."""
        mod = _import_fresh({"NETBRIDGE_VERIFY_SSL": "false"})
        ctx = mod.create_tunnel_ssl_context()
        # Verification should remain enabled because ALLOW_INSECURE is not set
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.check_hostname is True

    def test_verify_false_with_allow_insecure_disables_verification(self):
        """verify=False + ALLOW_INSECURE=1 must disable verification."""
        mod = _import_fresh({
            "NETBRIDGE_VERIFY_SSL": "false",
            "NETBRIDGE_ALLOW_INSECURE": "1",
        })
        ctx = mod.create_tunnel_ssl_context()
        assert ctx.verify_mode == ssl.CERT_NONE
        assert ctx.check_hostname is False

    def test_explicit_verify_false_without_allow_insecure(self):
        """Passing verify=False directly also requires ALLOW_INSECURE."""
        mod = _import_fresh()
        ctx = mod.create_tunnel_ssl_context(verify=False)
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_explicit_verify_false_with_allow_insecure(self):
        mod = _import_fresh({"NETBRIDGE_ALLOW_INSECURE": "1"})
        ctx = mod.create_tunnel_ssl_context(verify=False)
        assert ctx.verify_mode == ssl.CERT_NONE

    def test_warning_logged_when_insecure_ignored(self, caplog):
        """A warning should be logged when verify=False is ignored."""
        import logging

        mod = _import_fresh()
        with caplog.at_level(logging.WARNING, logger="shared_auth.connection"):
            mod.create_tunnel_ssl_context(verify=False)
        assert "NETBRIDGE_VERIFY_SSL=false ignored" in caplog.text


# ---------------------------------------------------------------------------
# CA bundle
# ---------------------------------------------------------------------------


class TestCaBundle:
    def test_ca_bundle_env_var(self, tmp_path):
        """NETBRIDGE_CA_BUNDLE env var should load the CA file."""
        ca_file = tmp_path / "ca.pem"
        # Create a minimal self-signed cert for load_verify_locations
        ca_file.write_text(_make_self_signed_pem())

        mod = _import_fresh({"NETBRIDGE_CA_BUNDLE": str(ca_file)})
        # Should not raise
        ctx = mod.create_tunnel_ssl_context()
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_ca_bundle_parameter_overrides_env(self, tmp_path):
        """Explicit ca_bundle parameter should take precedence over env var."""
        env_file = tmp_path / "env_ca.pem"
        param_file = tmp_path / "param_ca.pem"
        env_file.write_text(_make_self_signed_pem())
        param_file.write_text(_make_self_signed_pem())

        mod = _import_fresh({"NETBRIDGE_CA_BUNDLE": str(env_file)})
        # Should use param_file, not env_file
        ctx = mod.create_tunnel_ssl_context(ca_bundle=str(param_file))
        assert ctx.verify_mode == ssl.CERT_REQUIRED

    def test_invalid_ca_bundle_raises(self, tmp_path):
        """Invalid CA bundle path should raise an error."""
        mod = _import_fresh()
        with pytest.raises((ssl.SSLError, FileNotFoundError, OSError)):
            mod.create_tunnel_ssl_context(ca_bundle=str(tmp_path / "nonexistent.pem"))

    def test_ca_bundle_with_verify_true(self, tmp_path):
        """CA bundle should work alongside normal verification."""
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text(_make_self_signed_pem())

        mod = _import_fresh()
        ctx = mod.create_tunnel_ssl_context(verify=True, ca_bundle=str(ca_file))
        assert ctx.verify_mode == ssl.CERT_REQUIRED


# ---------------------------------------------------------------------------
# create_tunnel_connector
# ---------------------------------------------------------------------------


class TestCreateTunnelConnector:
    def test_passes_ca_bundle_to_ssl_context(self, tmp_path):
        """create_tunnel_connector should forward ca_bundle to create_tunnel_ssl_context."""
        ca_file = tmp_path / "ca.pem"
        ca_file.write_text(_make_self_signed_pem())

        mod = _import_fresh()
        calls = []
        original = mod.create_tunnel_ssl_context

        def tracking_wrapper(**kwargs):
            calls.append(kwargs)
            return original(**kwargs)

        with patch.object(mod, "create_tunnel_ssl_context", side_effect=tracking_wrapper):
            # Patch TCPConnector to avoid needing a running event loop
            with patch("aiohttp.TCPConnector"):
                mod.create_tunnel_connector(ca_bundle=str(ca_file))

        assert len(calls) == 1
        assert calls[0]["ca_bundle"] == str(ca_file)


# ---------------------------------------------------------------------------
# PEM helper
# ---------------------------------------------------------------------------


def _make_self_signed_pem() -> str:
    """Generate a minimal self-signed PEM certificate for testing."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime

    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "test-ca"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()
