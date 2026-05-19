"""Stream intercept for magic hostnames.

When the relay requests a TCP connection to a "magic" hostname like
``netbridge-exec``, the agent redirects the stream to an in-process
HTTP server instead of opening a real TCP connection.  This module
provides the hostname check and the internal server wrapper.
"""

from __future__ import annotations

import logging
from typing import Optional

from aiohttp import web

logger = logging.getLogger(__name__)

# Magic hostnames that trigger interception instead of real TCP connect.
MAGIC_HOSTS: set[str] = {"netbridge-exec"}


def is_magic_hostname(host: str) -> bool:
    """Check if *host* is a magic hostname (case-insensitive)."""
    return host.lower() in MAGIC_HOSTS


class InterceptServer:
    """In-process HTTP server for intercepted magic-hostname streams.

    Runs the remote_exec aiohttp app on an ephemeral loopback port.
    The agent connects intercepted streams to this port instead of
    opening real TCP connections.
    """

    def __init__(self) -> None:
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.port: Optional[int] = None

    async def start(self) -> None:
        """Start the internal HTTP server on an ephemeral loopback port."""
        from .remote_exec import create_app

        app = create_app()
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)  # port 0 = ephemeral
        await self._site.start()
        sockets = self._site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]
        logger.info("InterceptServer listening on 127.0.0.1:%d", self.port)

    async def stop(self) -> None:
        """Stop the internal HTTP server and release resources."""
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self.port = None
            logger.info("InterceptServer stopped")
