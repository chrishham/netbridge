"""Shared fixtures for netbridge-agent tests."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.fixture
def mock_reader():
    """Create a mock asyncio.StreamReader."""
    reader = AsyncMock(spec=asyncio.StreamReader)
    return reader


@pytest.fixture
def mock_writer():
    """Create a mock asyncio.StreamWriter with working close/wait_closed."""
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    writer.get_extra_info = MagicMock(return_value=None)
    return writer
