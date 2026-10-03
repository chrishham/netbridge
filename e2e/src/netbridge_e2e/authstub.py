"""Local JWKS stub for e2e auth testing.

Provides an HTTP server that serves JWKS (public keys) and mints signed tokens.
"""
import base64
import json
import os
import secrets
import shutil
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import jwtmint
from .stack import TEST_TENANT


class AuthStub:
    """Local JWKS stub that mints signed test tokens.

    Generates an RSA key pair, serves the public key as JWKS over HTTP,
    and provides methods to mint tokens signed with the private key.
    """

    def __init__(self, work: Path, tenant: str = TEST_TENANT):
        """Initialize AuthStub.

        Args:
            work: Working directory (for logs, etc). Key is NOT stored here.
            tenant: Azure tenant ID
        """
        self.tenant = tenant
        self.kid = secrets.token_hex(8)
        self._work = work
        self._key = None
        self._key_dir = None
        self.key_path = None
        self._server = None
        self._server_thread = None
        self._request_count = 0
        self._request_lock = threading.Lock()
        self.jwks_url = None

    def start(self):
        """Start the JWKS HTTP server."""
        # Generate RSA key
        self._key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Write private key to a secure temp directory (NOT under work)
        self._key_dir = tempfile.mkdtemp(prefix="nb-e2e-key-")
        self.key_path = Path(self._key_dir) / "key.pem"

        # Write with mode 0600
        pem = self._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Use os.open with 0o600 mode on POSIX
        if os.name == "posix":
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            try:
                os.write(fd, pem)
            finally:
                os.close(fd)
        else:
            # On Windows, just write normally
            self.key_path.write_bytes(pem)

        # Build JWKS
        public_key = self._key.public_key()
        public_numbers = public_key.public_numbers()

        def int_to_b64url(num: int) -> str:
            """Convert integer to base64url without padding."""
            byte_length = (num.bit_length() + 7) // 8
            num_bytes = num.to_bytes(byte_length, byteorder="big")
            return base64.urlsafe_b64encode(num_bytes).rstrip(b"=").decode("ascii")

        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": int_to_b64url(public_numbers.n),
                    "e": int_to_b64url(public_numbers.e),
                }
            ]
        }

        # Create HTTP server
        stub = self

        class JWKSHandler(BaseHTTPRequestHandler):
            """Handler that serves JWKS only on the correct path."""

            def log_message(self, format, *args):
                """Silence logging."""
                pass

            def do_GET(self):
                expected_path = f"/{stub.tenant}/discovery/v2.0/keys"
                if self.path == expected_path:
                    # Serve JWKS
                    with stub._request_lock:
                        stub._request_count += 1

                    response = json.dumps(jwks).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                else:
                    # 404 for all other paths (don't count these)
                    self.send_response(404)
                    self.end_headers()

        # Start server on loopback with random port
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), JWKSHandler)
        port = self._server.server_port
        self.jwks_url = f"http://127.0.0.1:{port}/{self.tenant}/discovery/v2.0/keys"

        # Run server in daemon thread
        self._server_thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._server_thread.start()

    def close(self):
        """Stop the server and clean up resources."""
        if self._server:
            self._server.shutdown()
            self._server_thread.join(timeout=5)
            self._server = None

        # Remove key directory
        if self._key_dir and Path(self._key_dir).exists():
            shutil.rmtree(self._key_dir)
            self._key_dir = None
            self.key_path = None

    def mint(self, **kw) -> str:
        """Mint a token signed with this stub's key.

        Args:
            **kw: Arguments passed to jwtmint.mint

        Returns:
            JWT token string
        """
        return jwtmint.mint(self._key, self.kid, self.tenant, **kw)

    def foreign_mint(self, **kw) -> str:
        """Mint a token signed with a different key but claiming this stub's kid.

        This produces a token that will fail signature verification.

        Args:
            **kw: Arguments passed to jwtmint.mint

        Returns:
            JWT token string
        """
        # Generate a fresh key
        foreign_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        # Sign with the foreign key but use our kid
        return jwtmint.mint(foreign_key, self.kid, self.tenant, **kw)

    def requests(self) -> int:
        """Return count of JWKS requests served."""
        with self._request_lock:
            return self._request_count

    def env(self) -> dict:
        """Return environment dict for fake az to use this stub."""
        return {
            "NETBRIDGE_E2E_SIGNING_KEY": str(self.key_path),
            "NETBRIDGE_E2E_KID": self.kid,
            "NETBRIDGE_E2E_TENANT": self.tenant,
        }
