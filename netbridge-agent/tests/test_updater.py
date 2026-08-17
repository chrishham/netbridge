import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from netbridge_agent.updater import (
    UpdateInfo,
    check_for_update,
    download_update,
)


class TestCheckForUpdate:
    @pytest.fixture
    def mock_session(self):
        session = MagicMock()
        response = AsyncMock()
        response.status = 200
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        session.get = Mock(return_value=response)
        return session, response

    async def test_newer_version_available(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v2.0.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is not None
        assert result.version == "2.0.0"
        assert result.download_url == "https://example.com/netbridge.exe"

    async def test_same_version_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v1.0.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_older_version_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v0.9.0",
            "assets": [{"name": "netbridge.exe", "browser_download_url": "https://example.com/netbridge.exe"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_dev_version_skips_check(self, mock_session):
        """Version 0.0.0 means dev/source — never prompt for update."""
        session, _ = mock_session
        with patch("netbridge_agent.updater.APP_VERSION", "0.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_http_error_returns_none(self, mock_session):
        session, response = mock_session
        response.status = 404
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_network_error_returns_none(self):
        session = AsyncMock()
        session.get.side_effect = Exception("network error")
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_non_agent_tag_skipped(self, mock_session):
        """Tags like socks-v2.0.0 should not trigger agent updates."""
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "socks-v2.0.0",
            "assets": [],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None

    async def test_no_exe_asset_returns_none(self, mock_session):
        session, response = mock_session
        response.json = AsyncMock(return_value={
            "tag_name": "agent-v2.0.0",
            "assets": [{"name": "other.zip", "browser_download_url": "https://example.com/other.zip"}],
        })
        with patch("netbridge_agent.updater.APP_VERSION", "1.0.0"):
            result = await check_for_update(session)
        assert result is None


class TestDownloadUpdate:
    async def test_downloads_to_dest(self, tmp_path):
        dest = tmp_path / "netbridge.exe"
        content = b"fake exe content"

        response = AsyncMock()
        response.status = 200
        response.content = MagicMock()
        # Simulate aiohttp's async chunked read
        chunks = [content, b""]
        response.content.read = AsyncMock(side_effect=chunks)
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)

        session = MagicMock()
        session.get = Mock(return_value=response)

        result = await download_update(session, "https://example.com/netbridge.exe", dest)
        assert result == dest
        assert dest.read_bytes() == content

    async def test_download_failure_raises(self, tmp_path):
        dest = tmp_path / "netbridge.exe"
        response = AsyncMock()
        response.status = 404
        response.__aenter__ = AsyncMock(return_value=response)
        response.__aexit__ = AsyncMock(return_value=False)
        session = MagicMock()
        session.get = Mock(return_value=response)

        with pytest.raises(RuntimeError, match="Download failed"):
            await download_update(session, "https://example.com/netbridge.exe", dest)
