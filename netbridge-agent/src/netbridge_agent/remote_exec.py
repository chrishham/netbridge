"""HTTP handlers for remote file and command operations.

These handlers are embedded inside the netbridge tunnel agent and served
by an internal InterceptServer.  They are only reachable through the
Azure AD-authenticated tunnel **and** only when the user has manually
toggled "Remote Exec" ON from the VDI system tray.  There is no
handler-level authentication — the trust boundary is the tunnel + tray
toggle.

Handlers must **never** let exceptions propagate — an uncaught exception
would crash the tunnel.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import socket

from aiohttp import web

from .config import get_app_dir

LOG = logging.getLogger(__name__)

_50_MB = 50 * 1024 * 1024


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _resolve_path(raw: str) -> str:
    """Return *raw* as an absolute normalised path.

    If *raw* is already absolute, normalise and return it.
    Otherwise join it with the current working directory.
    """
    if os.path.isabs(raw):
        return os.path.normpath(raw)
    return os.path.normpath(os.path.join(os.getcwd(), raw))


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


async def handle_health(request: web.Request) -> web.Response:
    """Return agent status and identity information."""
    try:
        hostname = socket.gethostname()
        try:
            local_ip = socket.gethostbyname(hostname)
        except Exception:
            local_ip = "unknown"
        return web.json_response(
            {
                "status": "ok",
                "hostname": hostname,
                "ip": local_ip,
                "cwd": os.getcwd(),
                "pid": os.getpid(),
            }
        )
    except Exception as exc:
        LOG.exception("handle_health failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# /files  — directory listing, read, write, delete
# ---------------------------------------------------------------------------


async def handle_file_list(request: web.Request) -> web.Response:
    """List directory contents sorted by name."""
    try:
        dir_path = request.query.get("dir", os.getcwd())
        dir_path = _resolve_path(dir_path)

        if not os.path.isdir(dir_path):
            return web.json_response(
                {"error": f"directory not found: {dir_path}"}, status=404
            )

        entries = []
        for name in sorted(os.listdir(dir_path)):
            full = os.path.join(dir_path, name)
            try:
                st = os.stat(full)
                entries.append(
                    {
                        "name": name,
                        "is_dir": os.path.isdir(full),
                        "size": st.st_size,
                        "mtime": st.st_mtime,
                    }
                )
            except OSError:
                entries.append(
                    {"name": name, "is_dir": False, "size": 0, "mtime": 0}
                )

        return web.json_response({"dir": dir_path, "entries": entries})
    except Exception as exc:
        LOG.exception("handle_file_list failed")
        return web.json_response({"error": "internal error"}, status=500)


async def handle_file_read(request: web.Request) -> web.Response:
    """Read / download a file."""
    try:
        raw = request.match_info["path"]
        file_path = _resolve_path(raw)

        if not os.path.isfile(file_path):
            return web.json_response(
                {"error": f"file not found: {file_path}"}, status=404
            )

        return web.FileResponse(file_path)
    except Exception as exc:
        LOG.exception("handle_file_read failed")
        return web.json_response({"error": "internal error"}, status=500)


async def handle_file_write(request: web.Request) -> web.Response:
    """Write / upload a file, creating parent directories as needed."""
    try:
        raw = request.match_info["path"]
        file_path = _resolve_path(raw)

        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        data = await request.read()
        with open(file_path, "wb") as f:
            f.write(data)

        return web.json_response(
            {"status": "ok", "path": file_path, "size": len(data)}
        )
    except Exception as exc:
        LOG.exception("handle_file_write failed")
        return web.json_response({"error": "internal error"}, status=500)


async def handle_file_delete(request: web.Request) -> web.Response:
    """Delete a file or directory (recursive for directories)."""
    try:
        raw = request.match_info["path"]
        file_path = _resolve_path(raw)

        if os.path.isdir(file_path):
            shutil.rmtree(file_path)
        elif os.path.isfile(file_path):
            os.remove(file_path)
        else:
            return web.json_response(
                {"error": f"not found: {file_path}"}, status=404
            )

        return web.json_response({"status": "ok", "deleted": file_path})
    except Exception as exc:
        LOG.exception("handle_file_delete failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# /exec  — command execution
# ---------------------------------------------------------------------------


async def handle_exec(request: web.Request) -> web.Response:
    """Run a shell command and return stdout/stderr/exit_code."""
    try:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid JSON body"}, status=400
            )

        cmd = body.get("cmd")
        if not cmd:
            return web.json_response({"error": "missing 'cmd'"}, status=400)

        cwd = body.get("cwd", os.getcwd())
        timeout = body.get("timeout", 300)

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
            return web.json_response(
                {
                    "exit_code": proc.returncode,
                    "stdout": stdout.decode("utf-8", errors="replace"),
                    "stderr": stderr.decode("utf-8", errors="replace"),
                }
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return web.json_response(
                {"error": f"timed out after {timeout}s"}, status=504
            )

    except Exception as exc:
        LOG.exception("handle_exec failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# /exec/stream  — streaming command execution
# ---------------------------------------------------------------------------


async def handle_exec_stream(request: web.Request) -> web.Response:
    """Run a shell command and stream output line-by-line."""
    try:
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": "invalid JSON body"}, status=400
            )

        cmd = body.get("cmd")
        if not cmd:
            return web.json_response({"error": "missing 'cmd'"}, status=400)

        cwd = body.get("cwd", os.getcwd())
        timeout = body.get("timeout", 600)

        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
        )

        resp = web.StreamResponse(
            status=200,
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        await resp.prepare(request)

        try:
            async def _read_lines():
                assert proc.stdout is not None
                async for line in proc.stdout:
                    await resp.write(line)

            await asyncio.wait_for(_read_lines(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            await resp.write(f"\n[timed out after {timeout}s]\n".encode())

        await proc.wait()
        await resp.write(f"\nexit code: {proc.returncode}\n".encode())
        await resp.write_eof()
        return resp

    except Exception as exc:
        LOG.exception("handle_exec_stream failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# /plugins  — plugin listing and hot-reload
# ---------------------------------------------------------------------------


def _get_plugins_dir():
    """Return the plugins directory path. Extracted for test overrides."""
    return get_app_dir() / "plugins"


async def handle_plugins(request: web.Request) -> web.Response:
    """List installed plugins."""
    try:
        from .plugin_loader import discover_plugins

        plugins_dir = _get_plugins_dir()
        manifests = discover_plugins(plugins_dir)
        return web.json_response({
            "plugins": [
                {
                    "name": m.name,
                    "hostname": m.hostname,
                    "description": m.description,
                    "version": m.version,
                }
                for m in manifests
            ]
        })
    except Exception:
        LOG.exception("handle_plugins failed")
        return web.json_response({"error": "internal error"}, status=500)


async def handle_plugins_reload(request: web.Request) -> web.Response:
    """Trigger re-discovery of plugins. Called after install/uninstall."""
    try:
        reload_fn = request.app.get("_plugin_reload_callback")
        if not reload_fn:
            return web.json_response(
                {"error": "reload not available"}, status=501
            )
        added, removed = await reload_fn()
        return web.json_response({
            "status": "ok",
            "added": added,
            "removed": removed,
        })
    except Exception:
        LOG.exception("handle_plugins_reload failed")
        return web.json_response({"error": "internal error"}, status=500)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def create_app() -> web.Application:
    """Create and return the aiohttp application with all routes."""
    app = web.Application(client_max_size=_50_MB)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/files", handle_file_list)
    app.router.add_get("/files/{path:.+}", handle_file_read)
    app.router.add_put("/files/{path:.+}", handle_file_write)
    app.router.add_delete("/files/{path:.+}", handle_file_delete)
    app.router.add_post("/exec", handle_exec)
    app.router.add_post("/exec/stream", handle_exec_stream)
    app.router.add_get("/plugins", handle_plugins)
    app.router.add_post("/plugins/reload", handle_plugins_reload)
    return app
