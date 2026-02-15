"""
SOCKS5 Protocol Handler

Implements the SOCKS5 handshake and CONNECT command per RFC 1928.
"""

import asyncio
import hmac
import logging
import socket
import struct
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .tunnel import TunnelManager

logger = logging.getLogger(__name__)

# Handshake timeout - maximum time to wait for client to send handshake data
HANDSHAKE_TIMEOUT = 30.0  # seconds

# SOCKS5 constants
SOCKS5_VERSION = 0x05

# Authentication methods
AUTH_NO_AUTH = 0x00
AUTH_GSSAPI = 0x01
AUTH_USERNAME_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REPLY_SUCCESS = 0x00
REPLY_GENERAL_FAILURE = 0x01
REPLY_NOT_ALLOWED = 0x02
REPLY_NETWORK_UNREACHABLE = 0x03
REPLY_HOST_UNREACHABLE = 0x04
REPLY_CONNECTION_REFUSED = 0x05
REPLY_TTL_EXPIRED = 0x06
REPLY_COMMAND_NOT_SUPPORTED = 0x07
REPLY_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Error(Exception):
    """SOCKS5 protocol error."""

    def __init__(self, reply_code: int, message: str):
        self.reply_code = reply_code
        super().__init__(message)


async def handle_socks5_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    tunnel: "TunnelManager",
    proxy_credentials: tuple[str, str] | None = None,
) -> None:
    """
    Handle incoming SOCKS5 connection from a client (browser/kubectl).

    Protocol flow:
    1. Client greeting (version + auth methods)
    2. Server auth selection (no auth / username-password)
    3. Client request (CONNECT to host:port)
    4. Server reply (success/failure)
    5. Bidirectional data forwarding
    """
    client_addr = writer.get_extra_info("peername")
    stream_id: str | None = None

    try:
        # Step 1: Handle greeting (and auth if credentials required)
        await _handle_greeting(reader, writer, proxy_credentials)

        # Step 2: Handle CONNECT request
        host, port = await _handle_request(reader, writer)
        logger.info(f"SOCKS5 {client_addr} -> CONNECT {host}:{port}")

        # Step 3: Establish connection through tunnel
        try:
            stream_id = await tunnel.connect(host, port)
        except asyncio.TimeoutError:
            await _send_reply(writer, REPLY_TTL_EXPIRED)
            return
        except ConnectionError as e:
            logger.warning(f"SOCKS5 connection failed: {e}")
            await _send_reply(writer, REPLY_HOST_UNREACHABLE)
            return
        except Exception as e:
            logger.error(f"SOCKS5 tunnel error: {e}")
            await _send_reply(writer, REPLY_GENERAL_FAILURE)
            return

        # Step 4: Send success reply
        await _send_reply(writer, REPLY_SUCCESS)

        # Step 5: Bidirectional forwarding
        await tunnel.forward(stream_id, reader, writer)

    except Socks5Error as e:
        logger.warning(f"SOCKS5 protocol error: {e}")
        try:
            await _send_reply(writer, e.reply_code)
        except Exception:
            pass
    except asyncio.TimeoutError:
        logger.warning(f"SOCKS5 handshake timeout: {client_addr}")
    except asyncio.IncompleteReadError:
        logger.warning(f"SOCKS5 client disconnected early: {client_addr}")
    except ConnectionResetError:
        logger.warning(f"SOCKS5 connection reset: {client_addr}")
    except Exception as e:
        logger.error(f"SOCKS5 unexpected error: {type(e).__name__}: {e}")
    finally:
        # Clean up stream if it was created
        if stream_id:
            await tunnel.close_stream(stream_id)

        # Close writer
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _handle_greeting(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    proxy_credentials: tuple[str, str] | None = None,
) -> None:
    """Handle SOCKS5 greeting (auth negotiation).

    If proxy_credentials is set, requires username/password auth (RFC 1929).
    Otherwise accepts no-auth.
    """
    # Read version and number of auth methods (with timeout)
    header = await asyncio.wait_for(reader.readexactly(2), timeout=HANDSHAKE_TIMEOUT)
    version, nmethods = struct.unpack("!BB", header)

    if version != SOCKS5_VERSION:
        raise Socks5Error(REPLY_GENERAL_FAILURE, f"Invalid version: {version}")

    # Read auth methods (with timeout)
    methods = await asyncio.wait_for(reader.readexactly(nmethods), timeout=HANDSHAKE_TIMEOUT)

    if proxy_credentials:
        # Require username/password auth (RFC 1929, method 0x02)
        if AUTH_USERNAME_PASSWORD not in methods:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, AUTH_NO_ACCEPTABLE))
            await writer.drain()
            raise Socks5Error(
                REPLY_NOT_ALLOWED,
                "Username/password auth required but not offered by client"
            )

        # Select username/password auth
        writer.write(struct.pack("!BB", SOCKS5_VERSION, AUTH_USERNAME_PASSWORD))
        await writer.drain()

        # RFC 1929 sub-negotiation
        auth_ver = await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT)
        if auth_ver != b"\x01":
            raise Socks5Error(REPLY_GENERAL_FAILURE, "Invalid auth sub-negotiation version")

        ulen = struct.unpack("!B", await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT))[0]
        username = (await asyncio.wait_for(reader.readexactly(ulen), timeout=HANDSHAKE_TIMEOUT)).decode("utf-8")

        plen = struct.unpack("!B", await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT))[0]
        password = (await asyncio.wait_for(reader.readexactly(plen), timeout=HANDSHAKE_TIMEOUT)).decode("utf-8")

        expected_user, expected_pass = proxy_credentials
        if not (hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_pass)):
            # Auth failure: version=0x01, status=0x01 (failure)
            writer.write(b"\x01\x01")
            await writer.drain()
            raise Socks5Error(REPLY_NOT_ALLOWED, "Authentication failed")

        # Auth success: version=0x01, status=0x00 (success)
        writer.write(b"\x01\x00")
        await writer.drain()
    else:
        # No credentials required - accept NO AUTH
        if AUTH_NO_AUTH not in methods:
            writer.write(struct.pack("!BB", SOCKS5_VERSION, AUTH_NO_ACCEPTABLE))
            await writer.drain()
            raise Socks5Error(REPLY_NOT_ALLOWED, "No acceptable auth method")

        writer.write(struct.pack("!BB", SOCKS5_VERSION, AUTH_NO_AUTH))
        await writer.drain()


async def _handle_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> tuple[str, int]:
    """Handle SOCKS5 CONNECT request. Returns (host, port)."""
    # Read request header: VER CMD RSV ATYP (with timeout)
    header = await asyncio.wait_for(reader.readexactly(4), timeout=HANDSHAKE_TIMEOUT)
    version, cmd, _, atyp = struct.unpack("!BBBB", header)

    if version != SOCKS5_VERSION:
        raise Socks5Error(REPLY_GENERAL_FAILURE, f"Invalid version: {version}")

    if cmd != CMD_CONNECT:
        raise Socks5Error(
            REPLY_COMMAND_NOT_SUPPORTED, f"Unsupported command: {cmd}"
        )

    # Parse destination address (with timeout for each read)
    if atyp == ATYP_IPV4:
        addr_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=HANDSHAKE_TIMEOUT)
        host = socket.inet_ntoa(addr_bytes)
    elif atyp == ATYP_DOMAIN:
        domain_len = struct.unpack("!B", await asyncio.wait_for(reader.readexactly(1), timeout=HANDSHAKE_TIMEOUT))[0]
        host = (await asyncio.wait_for(reader.readexactly(domain_len), timeout=HANDSHAKE_TIMEOUT)).decode("utf-8")
    elif atyp == ATYP_IPV6:
        addr_bytes = await asyncio.wait_for(reader.readexactly(16), timeout=HANDSHAKE_TIMEOUT)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise Socks5Error(
            REPLY_ADDRESS_TYPE_NOT_SUPPORTED, f"Unsupported address type: {atyp}"
        )

    # Parse port (with timeout)
    port = struct.unpack("!H", await asyncio.wait_for(reader.readexactly(2), timeout=HANDSHAKE_TIMEOUT))[0]

    return host, port


async def _send_reply(
    writer: asyncio.StreamWriter,
    reply_code: int,
    bind_addr: str = "0.0.0.0",
    bind_port: int = 0,
) -> None:
    """Send SOCKS5 reply to client."""
    # VER REP RSV ATYP BND.ADDR BND.PORT
    reply = struct.pack("!BBBB", SOCKS5_VERSION, reply_code, 0x00, ATYP_IPV4)
    reply += socket.inet_aton(bind_addr)
    reply += struct.pack("!H", bind_port)

    writer.write(reply)
    await writer.drain()
