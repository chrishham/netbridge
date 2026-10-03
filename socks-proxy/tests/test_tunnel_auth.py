"""Tests for TunnelManager's handling of relay auth rejections (401/403)."""

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from socks_proxy.tunnel import TunnelManager

E401 = ConnectionError("Authentication failed (401): rejected", 401)
E403 = ConnectionError("Access forbidden (403): rejected", 403)


def _manager(refresh=None, on_status=None):
    with patch("socks_proxy.tunnel.get_session_id", return_value="sid"):
        return TunnelManager(
            "relay.com", auth_token="tok0",
            token_refresh_callback=refresh, on_status_change=on_status,
        )


def _scripted_connect(tm, outcomes):
    """Replace _connect with one that records the token and replays outcomes."""
    seen = []
    script = list(outcomes)

    async def fake_connect():
        seen.append(tm.auth_token)
        outcome = script.pop(0)
        if outcome is not None:
            raise outcome
    tm._connect = fake_connect
    return seen


class TestInitialConnect:
    @pytest.mark.asyncio
    async def test_401_refreshes_token_then_403_is_permanent(self, caplog):
        caplog.set_level(logging.INFO, logger="socks_proxy")
        refresh = MagicMock(return_value="tok1")
        tm = _manager(refresh)
        seen = _scripted_connect(tm, [E401, E403])

        with patch("socks_proxy.tunnel.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(ConnectionError, match=r"\(403\)"):
                await tm.start()
        await tm.session.close()

        assert seen == ["tok0", "tok1"]
        assert "Token refreshed after auth failure" in caplog.text

    @pytest.mark.asyncio
    async def test_third_401_raises_even_though_refresh_succeeds(self):
        refresh = MagicMock(side_effect=["tok1", "tok2", "tok3"])
        tm = _manager(refresh)
        seen = _scripted_connect(tm, [E401, E401, E401, None])

        with patch("socks_proxy.tunnel.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(ConnectionError, match=r"\(401\)"):
                await tm.start()
        await tm.session.close()

        assert seen == ["tok0", "tok1", "tok2"]

    @pytest.mark.asyncio
    async def test_403_raises_without_retry(self):
        refresh = MagicMock(return_value="tok1")
        tm = _manager(refresh)
        seen = _scripted_connect(tm, [E403, None])

        with patch("socks_proxy.tunnel.asyncio.sleep", new_callable=AsyncMock):
            with pytest.raises(ConnectionError, match=r"\(403\)"):
                await tm.start()
        await tm.session.close()

        assert seen == ["tok0"]
        refresh.assert_not_called()


class TestReconnectLoop:
    async def _run_loop(self, tm):
        tm._receive_loop = AsyncMock()
        with patch("socks_proxy.tunnel.asyncio.sleep", new_callable=AsyncMock):
            await tm._connection_loop()

    @pytest.mark.asyncio
    async def test_three_401s_give_up(self, caplog):
        caplog.set_level(logging.INFO, logger="socks_proxy")
        on_status = MagicMock()
        tm = _manager(MagicMock(side_effect=["tok1", "tok2", "tok3"]), on_status)
        seen = _scripted_connect(tm, [E401, E401, E401])

        await self._run_loop(tm)

        assert seen == ["tok0", "tok1", "tok2"]
        assert tm._permanent_failure
        assert caplog.text.count("Token refreshed successfully") == 2
        assert "3 consecutive auth failures. Giving up." in caplog.text
        assert any(c.kwargs.get("auth_required") for c in on_status.call_args_list)

    @pytest.mark.asyncio
    async def test_403_is_permanent(self, caplog):
        caplog.set_level(logging.INFO, logger="socks_proxy")
        on_status = MagicMock()
        refresh = MagicMock(return_value="tok1")
        tm = _manager(refresh, on_status)
        seen = _scripted_connect(tm, [E403])

        await self._run_loop(tm)

        assert seen == ["tok0"]
        assert tm._permanent_failure
        assert "Access forbidden" in caplog.text
        refresh.assert_not_called()
        assert any(c.kwargs.get("permanent_failure") for c in on_status.call_args_list)
