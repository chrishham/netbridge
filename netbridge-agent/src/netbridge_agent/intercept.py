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

MAGIC_HOSTS: set[str] = {"netbridge-exec"}


def is_magic_hostname(host: str) -> bool:
    """Check if *host* is a magic hostname (case-insensitive)."""
    return host.lower() in MAGIC_HOSTS


class InterceptServer:
    """In-process HTTP server with hostname-based routing.

    Each registered hostname maps to its own aiohttp Application.
    Requests are dispatched by the Host header.  Apps can be added
    or removed at any time — even after the server is started.
    """

    def __init__(self) -> None:
        self._apps: dict[str, web.Application] = {}
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self.port: Optional[int] = None

    @property
    def registered_hostnames(self) -> set[str]:
        return set(self._apps)

    def register_app(self, hostname: str, app: web.Application) -> None:
        hostname = hostname.lower()
        self._apps[hostname] = app
        MAGIC_HOSTS.add(hostname)
        logger.info("Registered app: %s", hostname)

    def unregister_app(self, hostname: str) -> None:
        hostname = hostname.lower()
        self._apps.pop(hostname, None)
        MAGIC_HOSTS.discard(hostname)
        logger.info("Unregistered app: %s", hostname)

    async def start(self) -> None:
        server = self

        async def dispatch(request: web.Request) -> web.Response:
            host = request.host.split(":")[0].lower()
            sub_app = server._apps.get(host)
            if sub_app is None:
                return web.json_response(
                    {"error": f"unknown service: {host}"}, status=404
                )
            try:
                match = await sub_app.router.resolve(request)
                if isinstance(match, web.UrlMappingMatchInfo):
                    return await match.handler(request)
                return web.json_response({"error": "not found"}, status=404)
            except web.HTTPNotFound:
                return web.json_response({"error": "not found"}, status=404)
            except Exception:
                logger.exception("Handler error for %s", host)
                return web.json_response(
                    {"error": f"plugin error: {host}"}, status=500
                )

        dispatcher = web.Application()
        dispatcher.router.add_route("*", "/{path_info:.*}", dispatch)

        self._runner = web.AppRunner(dispatcher)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        sockets = self._site._server.sockets  # type: ignore[union-attr]
        self.port = sockets[0].getsockname()[1]
        logger.info("InterceptServer listening on 127.0.0.1:%d", self.port)

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self.port = None
            logger.info("InterceptServer stopped")
