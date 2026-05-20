"""Stream intercept for magic hostnames.

When the relay requests a TCP connection to a "magic" hostname like
``netbridge-exec``, the agent redirects the stream to an in-process
HTTP server instead of opening a real TCP connection.

The InterceptServer uses a catch-all dispatcher pattern: a single
aiohttp app with a wildcard route dispatches to sub-app routers
based on the HTTP Host header.  Apps can be registered and
unregistered at runtime (hot-plug) without restarting the server.
"""

from __future__ import annotations

import logging
from typing import Optional

from aiohttp import web

logger = logging.getLogger(__name__)

_BASE_MAGIC_HOSTS: frozenset[str] = frozenset({"netbridge-exec"})
_dynamic_hosts: set[str] = set()

MAGIC_HOSTS = _BASE_MAGIC_HOSTS | _dynamic_hosts


def is_magic_hostname(host: str) -> bool:
    """Check if *host* is a magic hostname (case-insensitive)."""
    return host.lower() in _BASE_MAGIC_HOSTS or host.lower() in _dynamic_hosts


class InterceptServer:
    """In-process HTTP server with hostname-based routing.

    Each registered hostname gets its own ``AppRunner`` and ephemeral
    loopback port.  The agent maps hostnames to ports via
    :meth:`port_for`.  Apps can be added or removed at any time.
    """

    def __init__(self) -> None:
        self._runners: dict[str, tuple[web.AppRunner, web.TCPSite, int]] = {}
        self._started = False
        self.port: Optional[int] = None

    @property
    def registered_hostnames(self) -> set[str]:
        return set(self._runners)

    def port_for(self, hostname: str) -> Optional[int]:
        entry = self._runners.get(hostname.lower())
        return entry[2] if entry else None

    async def register_app(self, hostname: str, app: web.Application) -> None:
        hostname = hostname.lower()
        if hostname in self._runners:
            await self.unregister_app(hostname)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        sockets = site._server.sockets  # type: ignore[union-attr]
        port = sockets[0].getsockname()[1]
        self._runners[hostname] = (runner, site, port)
        _dynamic_hosts.add(hostname)
        if self.port is None:
            self.port = port
        logger.info("Registered app: %s on 127.0.0.1:%d", hostname, port)

    async def unregister_app(self, hostname: str) -> None:
        hostname = hostname.lower()
        entry = self._runners.pop(hostname, None)
        if entry:
            runner, _, _ = entry
            await runner.cleanup()
        _dynamic_hosts.discard(hostname)
        if not self._runners:
            self.port = None
        else:
            self.port = next(iter(self._runners.values()))[2]
        logger.info("Unregistered app: %s", hostname)

    async def start(self) -> None:
        self._started = True
        if self._runners:
            self.port = next(iter(self._runners.values()))[2]
        logger.info("InterceptServer started (%d apps)", len(self._runners))

    async def stop(self) -> None:
        for hostname in list(self._runners):
            await self.unregister_app(hostname)
        self._started = False
        self.port = None
        logger.info("InterceptServer stopped")
