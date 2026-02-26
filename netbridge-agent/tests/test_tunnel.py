"""Tests for netbridge_agent.tunnel module."""

import asyncio
import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from netbridge_agent.tunnel import (
    ProxyConnectionError,
    _extract_challenge_token,
    _raise_for_status,
    _read_proxy_response,
    _select_auth_scheme,
    _send_connect_request,
    connect_via_proxy,
    parse_proxy_address,
)


def make_http_response(status: int, reason: str = "OK", headers: dict | None = None) -> list[bytes]:
    """Build raw HTTP response lines as a list of bytes for mock reader.readline()."""
    lines = [f"HTTP/1.1 {status} {reason}\r\n".encode()]
    if headers:
        for name, values in headers.items():
            if isinstance(values, str):
                values = [values]
            for v in values:
                lines.append(f"{name}: {v}\r\n".encode())
    lines.append(b"\r\n")
    return lines


# ---------------------------------------------------------------------------
# parse_proxy_address
# ---------------------------------------------------------------------------


class TestParseProxyAddress:
    def test_host_and_port(self):
        assert parse_proxy_address("proxy.corp:3128") == ("proxy.corp", 3128)

    def test_host_only_default_port(self):
        assert parse_proxy_address("proxy.corp") == ("proxy.corp", 8080)

    def test_invalid_port_default(self):
        assert parse_proxy_address("proxy.corp:abc") == ("proxy.corp", 8080)

    def test_ipv4(self):
        assert parse_proxy_address("10.0.0.1:8080") == ("10.0.0.1", 8080)


# ---------------------------------------------------------------------------
# _send_connect_request
# ---------------------------------------------------------------------------


class TestSendConnectRequest:
    @pytest.mark.asyncio
    async def test_basic_connect(self, mock_writer):
        await _send_connect_request(mock_writer, "example.com", 443)
        written = mock_writer.write.call_args[0][0].decode()
        assert "CONNECT example.com:443 HTTP/1.1" in written
        assert "Host: example.com:443" in written
        assert "Proxy-Authorization" not in written

    @pytest.mark.asyncio
    async def test_with_auth_header(self, mock_writer):
        await _send_connect_request(
            mock_writer, "example.com", 443,
            auth_header="Basic dXNlcjpwYXNz",
        )
        written = mock_writer.write.call_args[0][0].decode()
        assert "Proxy-Authorization: Basic dXNlcjpwYXNz" in written

    @pytest.mark.asyncio
    async def test_ends_with_blank_line(self, mock_writer):
        await _send_connect_request(mock_writer, "host", 80)
        written = mock_writer.write.call_args[0][0].decode()
        assert written.endswith("\r\n\r\n")


# ---------------------------------------------------------------------------
# _read_proxy_response
# ---------------------------------------------------------------------------


class TestReadProxyResponse:
    @pytest.mark.asyncio
    async def test_200_ok(self, mock_reader):
        lines = make_http_response(200, "Connection Established")
        mock_reader.readline = AsyncMock(side_effect=lines)

        status, headers = await _read_proxy_response(mock_reader)
        assert status == 200
        assert headers == {}

    @pytest.mark.asyncio
    async def test_407_with_headers(self, mock_reader):
        lines = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": ["Negotiate", "NTLM", "Basic realm=\"corp\""]},
        )
        mock_reader.readline = AsyncMock(side_effect=lines)

        status, headers = await _read_proxy_response(mock_reader)
        assert status == 407
        assert "proxy-authenticate" in headers
        assert len(headers["proxy-authenticate"]) == 3

    @pytest.mark.asyncio
    async def test_empty_response_raises(self, mock_reader):
        mock_reader.readline = AsyncMock(return_value=b"")
        with pytest.raises(ProxyConnectionError, match="closed connection"):
            await _read_proxy_response(mock_reader)

    @pytest.mark.asyncio
    async def test_malformed_status_raises(self, mock_reader):
        mock_reader.readline = AsyncMock(side_effect=[b"GARBAGE\r\n", b"\r\n"])
        with pytest.raises(ProxyConnectionError, match="Invalid proxy response"):
            await _read_proxy_response(mock_reader)

    @pytest.mark.asyncio
    async def test_non_numeric_status_raises(self, mock_reader):
        mock_reader.readline = AsyncMock(side_effect=[b"HTTP/1.1 abc OK\r\n", b"\r\n"])
        with pytest.raises(ProxyConnectionError, match="Invalid proxy response"):
            await _read_proxy_response(mock_reader)

    @pytest.mark.asyncio
    async def test_multi_value_headers_accumulated(self, mock_reader):
        lines = [
            b"HTTP/1.1 407 Proxy Authentication Required\r\n",
            b"Proxy-Authenticate: Negotiate\r\n",
            b"Proxy-Authenticate: NTLM\r\n",
            b"Content-Length: 0\r\n",
            b"\r\n",
        ]
        mock_reader.readline = AsyncMock(side_effect=lines)
        status, headers = await _read_proxy_response(mock_reader)
        assert status == 407
        assert headers["proxy-authenticate"] == ["Negotiate", "NTLM"]
        assert headers["content-length"] == ["0"]


# ---------------------------------------------------------------------------
# _select_auth_scheme
# ---------------------------------------------------------------------------


class TestSelectAuthScheme:
    def test_negotiate_preferred_over_ntlm(self):
        headers = {"proxy-authenticate": ["NTLM", "Negotiate", "Basic realm=\"x\""]}
        assert _select_auth_scheme(headers) == "Negotiate"

    def test_ntlm_when_no_negotiate(self):
        headers = {"proxy-authenticate": ["NTLM", "Basic realm=\"x\""]}
        assert _select_auth_scheme(headers) == "NTLM"

    def test_none_when_only_basic(self):
        headers = {"proxy-authenticate": ["Basic realm=\"x\""]}
        assert _select_auth_scheme(headers) is None

    def test_none_when_no_auth_header(self):
        assert _select_auth_scheme({}) is None

    def test_case_insensitive(self):
        headers = {"proxy-authenticate": ["negotiate"]}
        assert _select_auth_scheme(headers) == "Negotiate"

    def test_negotiate_with_token_body(self):
        headers = {"proxy-authenticate": ["Negotiate TlRMTVNTUAAB"]}
        assert _select_auth_scheme(headers) == "Negotiate"


# ---------------------------------------------------------------------------
# _extract_challenge_token
# ---------------------------------------------------------------------------


class TestExtractChallengeToken:
    def test_extracts_token(self):
        headers = {"proxy-authenticate": ["Negotiate TlRMTVNTUAAC..."]}
        token = _extract_challenge_token(headers, "Negotiate")
        assert token == "TlRMTVNTUAAC..."

    def test_no_token_body(self):
        headers = {"proxy-authenticate": ["Negotiate"]}
        assert _extract_challenge_token(headers, "Negotiate") is None

    def test_wrong_scheme(self):
        headers = {"proxy-authenticate": ["NTLM TlRMTVNTUAAC..."]}
        assert _extract_challenge_token(headers, "Negotiate") is None

    def test_case_insensitive_scheme(self):
        headers = {"proxy-authenticate": ["negotiate TlRMTVNTUAAC..."]}
        assert _extract_challenge_token(headers, "Negotiate") == "TlRMTVNTUAAC..."

    def test_no_headers(self):
        assert _extract_challenge_token({}, "Negotiate") is None


# ---------------------------------------------------------------------------
# _raise_for_status
# ---------------------------------------------------------------------------


class TestRaiseForStatus:
    def test_200_does_not_raise(self):
        _raise_for_status(200, "host", 443)  # should not raise

    def test_407_raises(self):
        with pytest.raises(ProxyConnectionError, match="authentication required") as exc_info:
            _raise_for_status(407, "host", 443)
        assert exc_info.value.status_code == 407

    def test_403_raises(self):
        with pytest.raises(ProxyConnectionError, match="denied") as exc_info:
            _raise_for_status(403, "host", 443)
        assert exc_info.value.status_code == 403

    def test_502_raises(self):
        with pytest.raises(ProxyConnectionError, match="Bad Gateway") as exc_info:
            _raise_for_status(502, "host", 443)
        assert exc_info.value.status_code == 502

    def test_504_raises(self):
        with pytest.raises(ProxyConnectionError, match="timeout") as exc_info:
            _raise_for_status(504, "host", 443)
        assert exc_info.value.status_code == 504

    def test_unknown_status_includes_reason(self):
        with pytest.raises(ProxyConnectionError, match="599.*Custom") as exc_info:
            _raise_for_status(599, "host", 443, ["HTTP/1.1", "599", "Custom"])
        assert exc_info.value.status_code == 599

    def test_unknown_status_no_parts(self):
        with pytest.raises(ProxyConnectionError, match="Unknown"):
            _raise_for_status(599, "host", 443)


# ---------------------------------------------------------------------------
# connect_via_proxy - success path
# ---------------------------------------------------------------------------


class TestConnectViaProxySuccess:
    @pytest.mark.asyncio
    async def test_200_returns_streams(self):
        """Unauthenticated CONNECT succeeds on first try."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(200, "Connection Established")
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)

            reader, writer = await connect_via_proxy("proxy", 8080, "target", 443)

        assert reader is mock_reader
        assert writer is mock_writer

    @pytest.mark.asyncio
    async def test_basic_auth_header_sent(self):
        """When proxy_auth is provided, Basic auth header is sent."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(200, "Connection Established")
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)

            await connect_via_proxy(
                "proxy", 8080, "target", 443,
                proxy_auth=("user", "pass"),
            )

        written = mock_writer.write.call_args[0][0].decode()
        expected_creds = base64.b64encode(b"user:pass").decode()
        assert f"Proxy-Authorization: Basic {expected_creds}" in written


# ---------------------------------------------------------------------------
# connect_via_proxy - error paths
# ---------------------------------------------------------------------------


class TestConnectViaProxyErrors:
    @pytest.mark.asyncio
    async def test_connection_refused(self):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.side_effect = OSError("Connection refused")
            with pytest.raises(ProxyConnectionError, match="Cannot connect"):
                await connect_via_proxy("proxy", 8080, "target", 443)

    @pytest.mark.asyncio
    async def test_403_raises_and_closes(self):
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(403, "Forbidden")
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)
            with pytest.raises(ProxyConnectionError, match="denied"):
                await connect_via_proxy("proxy", 8080, "target", 443)

        mock_writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_407_without_sspi_raises(self):
        """On non-Windows (or no Negotiate/NTLM), 407 should raise."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": "Basic realm=\"corp\""},
        )
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.return_value = (mock_reader, mock_writer)
            with pytest.raises(ProxyConnectionError, match="authentication required"):
                await connect_via_proxy("proxy", 8080, "target", 443)

    @pytest.mark.asyncio
    async def test_timeout_cleans_up(self):
        """Timeout during connection should raise ProxyConnectionError."""
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
            mock_open.side_effect = asyncio.TimeoutError()
            with pytest.raises((asyncio.TimeoutError, ProxyConnectionError)):
                await connect_via_proxy("proxy", 8080, "target", 443)


# ---------------------------------------------------------------------------
# connect_via_proxy - SSPI handshake (mocked)
# ---------------------------------------------------------------------------


class TestConnectViaProxySSPI:
    @pytest.mark.asyncio
    async def test_sspi_handshake_attempted_on_win32(self):
        """When platform is win32 and 407+Negotiate, SSPI handshake is attempted."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        # First request: 407 with Negotiate
        response_407 = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": ["Negotiate", "NTLM"]},
        )
        # After SSPI handshake: 200
        response_200 = make_http_response(200, "Connection Established")

        mock_reader.readline = AsyncMock(side_effect=response_407 + response_200)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open, \
             patch("netbridge_agent.tunnel.sys") as mock_sys, \
             patch("netbridge_agent.tunnel._sspi_handshake", new_callable=AsyncMock) as mock_sspi:

            mock_open.return_value = (mock_reader, mock_writer)
            mock_sys.platform = "win32"
            mock_sspi.return_value = (200, {})

            reader, writer = await connect_via_proxy("proxy", 8080, "target", 443)

        mock_sspi.assert_called_once()
        assert reader is mock_reader

    @pytest.mark.asyncio
    async def test_sspi_skipped_on_linux(self):
        """On Linux, SSPI is not attempted even if Negotiate is offered."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": ["Negotiate", "NTLM"]},
        )
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open, \
             patch("netbridge_agent.tunnel.sys") as mock_sys:

            mock_open.return_value = (mock_reader, mock_writer)
            mock_sys.platform = "linux"

            with pytest.raises(ProxyConnectionError, match="authentication required"):
                await connect_via_proxy("proxy", 8080, "target", 443)

    @pytest.mark.asyncio
    async def test_sspi_failure_falls_through_to_error(self):
        """If SSPI handshake fails, the original 407 error is raised."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": "Negotiate"},
        )
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open, \
             patch("netbridge_agent.tunnel.sys") as mock_sys, \
             patch("netbridge_agent.tunnel._sspi_handshake", new_callable=AsyncMock) as mock_sspi:

            mock_open.return_value = (mock_reader, mock_writer)
            mock_sys.platform = "win32"
            mock_sspi.side_effect = RuntimeError("SSPI init failed")

            with pytest.raises(ProxyConnectionError, match="authentication required"):
                await connect_via_proxy("proxy", 8080, "target", 443)

    @pytest.mark.asyncio
    async def test_sspi_returns_non_200_raises(self):
        """If SSPI handshake returns a non-200 status, an error is raised."""
        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        lines = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": "Negotiate"},
        )
        mock_reader.readline = AsyncMock(side_effect=lines)

        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open, \
             patch("netbridge_agent.tunnel.sys") as mock_sys, \
             patch("netbridge_agent.tunnel._sspi_handshake", new_callable=AsyncMock) as mock_sspi:

            mock_open.return_value = (mock_reader, mock_writer)
            mock_sys.platform = "win32"
            mock_sspi.return_value = (403, {})

            with pytest.raises(ProxyConnectionError, match="denied"):
                await connect_via_proxy("proxy", 8080, "target", 443)


# ---------------------------------------------------------------------------
# _sspi_handshake (mocking SSPIAuth)
# ---------------------------------------------------------------------------


class TestSSPIHandshake:
    """Test _sspi_handshake with a mocked SSPIAuth class."""

    @pytest.mark.asyncio
    async def test_full_three_step_handshake(self):
        """Type1 → 407+challenge → Type3 → 200."""
        from netbridge_agent.tunnel import _sspi_handshake

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        # After Type 1: proxy returns 407 with challenge
        resp_407 = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": "Negotiate TlRMTVNTUAAC..."},
        )
        # After Type 3: proxy returns 200
        resp_200 = make_http_response(200, "Connection Established")

        mock_reader.readline = AsyncMock(side_effect=resp_407 + resp_200)

        mock_auth = MagicMock()
        mock_auth.get_initial_token.return_value = "TYPE1TOKEN"
        mock_auth.get_response_token.return_value = "TYPE3TOKEN"
        mock_auth.close = MagicMock()

        with patch("netbridge_agent.winauth.SSPIAuth", return_value=mock_auth):
            status, headers = await _sspi_handshake(
                mock_reader, mock_writer,
                "target.com", 443, "proxy.corp", "Negotiate",
                challenge_headers={},
            )

        assert status == 200
        mock_auth.get_initial_token.assert_called_once_with("HTTP/proxy.corp")
        mock_auth.get_response_token.assert_called_once_with("HTTP/proxy.corp", "TlRMTVNTUAAC...")
        mock_auth.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_single_step_handshake(self):
        """Proxy accepts Type 1 immediately → 200."""
        from netbridge_agent.tunnel import _sspi_handshake

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        resp_200 = make_http_response(200, "Connection Established")
        mock_reader.readline = AsyncMock(side_effect=resp_200)

        mock_auth = MagicMock()
        mock_auth.get_initial_token.return_value = "TOKEN"
        mock_auth.close = MagicMock()

        with patch("netbridge_agent.winauth.SSPIAuth", return_value=mock_auth):
            status, _ = await _sspi_handshake(
                mock_reader, mock_writer,
                "target.com", 443, "proxy.corp", "Negotiate",
                challenge_headers={},
            )

        assert status == 200
        mock_auth.get_response_token.assert_not_called()

    @pytest.mark.asyncio
    async def test_initial_407_has_challenge(self):
        """Initial 407 already contains challenge token (some proxies do this)."""
        from netbridge_agent.tunnel import _sspi_handshake

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        resp_200 = make_http_response(200, "Connection Established")
        mock_reader.readline = AsyncMock(side_effect=resp_200)

        mock_auth = MagicMock()
        mock_auth.get_response_token.return_value = "RESPONSE_TOKEN"
        mock_auth.close = MagicMock()

        challenge_headers = {"proxy-authenticate": ["Negotiate INITIAL_CHALLENGE"]}

        with patch("netbridge_agent.winauth.SSPIAuth", return_value=mock_auth):
            status, _ = await _sspi_handshake(
                mock_reader, mock_writer,
                "target.com", 443, "proxy.corp", "Negotiate",
                challenge_headers=challenge_headers,
            )

        assert status == 200
        # Should use get_response_token with the challenge, not get_initial_token
        mock_auth.get_initial_token.assert_not_called()
        mock_auth.get_response_token.assert_called_once_with("HTTP/proxy.corp", "INITIAL_CHALLENGE")

    @pytest.mark.asyncio
    async def test_407_without_challenge_raises(self):
        """407 response without challenge token after Type 1 should raise."""
        from netbridge_agent.tunnel import _sspi_handshake

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        # 407 without challenge token body
        resp_407 = make_http_response(
            407, "Proxy Authentication Required",
            headers={"Proxy-Authenticate": "Negotiate"},
        )
        mock_reader.readline = AsyncMock(side_effect=resp_407)

        mock_auth = MagicMock()
        mock_auth.get_initial_token.return_value = "TOKEN"
        mock_auth.close = MagicMock()

        with patch("netbridge_agent.winauth.SSPIAuth", return_value=mock_auth):
            with pytest.raises(ProxyConnectionError, match="without.*challenge"):
                await _sspi_handshake(
                    mock_reader, mock_writer,
                    "target.com", 443, "proxy.corp", "Negotiate",
                    challenge_headers={},
                )

        # close() should still be called in finally block
        mock_auth.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_sspi_auth_closed_on_error(self):
        """SSPIAuth.close() must be called even if an error occurs."""
        from netbridge_agent.tunnel import _sspi_handshake

        mock_reader = AsyncMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        mock_writer.write = MagicMock()
        mock_writer.drain = AsyncMock()

        mock_auth = MagicMock()
        mock_auth.get_initial_token.side_effect = RuntimeError("SSPI error")
        mock_auth.close = MagicMock()

        with patch("netbridge_agent.winauth.SSPIAuth", return_value=mock_auth):
            with pytest.raises(RuntimeError, match="SSPI error"):
                await _sspi_handshake(
                    mock_reader, mock_writer,
                    "target.com", 443, "proxy.corp", "Negotiate",
                    challenge_headers={},
                )

        mock_auth.close.assert_called_once()
