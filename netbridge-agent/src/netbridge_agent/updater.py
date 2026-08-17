import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import aiohttp
from packaging.version import Version

from .config import APP_VERSION

logger = logging.getLogger(__name__)

GITHUB_API_URL = "https://api.github.com/repos/chrishham/netbridge/releases/latest"


@dataclass
class UpdateInfo:
    version: str
    download_url: str


async def check_for_update(session: aiohttp.ClientSession) -> Optional[UpdateInfo]:
    """Check GitHub for a newer agent release.

    Returns UpdateInfo if a newer version is available, None otherwise.
    Silently returns None on any error (network, parse, etc).
    """
    if APP_VERSION == "0.0.0":
        return None

    try:
        async with session.get(
            GITHUB_API_URL,
            headers={"Accept": "application/vnd.github+json"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                return None
            data = await resp.json()
    except Exception:
        logger.debug("Update check failed", exc_info=True)
        return None

    tag = data.get("tag_name", "")
    if not tag.startswith("agent-v"):
        return None

    remote_version = tag.removeprefix("agent-v")
    try:
        if Version(remote_version) <= Version(APP_VERSION):
            return None
    except Exception:
        return None

    assets = data.get("assets", [])
    for asset in assets:
        if asset.get("name") == "netbridge.exe":
            return UpdateInfo(
                version=remote_version,
                download_url=asset["browser_download_url"],
            )

    return None


CHUNK_SIZE = 64 * 1024


async def download_update(
    session: aiohttp.ClientSession,
    url: str,
    dest: Path,
) -> Path:
    """Download the update exe to dest. Raises RuntimeError on failure."""
    async with session.get(url, timeout=aiohttp.ClientTimeout(total=300)) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Download failed: HTTP {resp.status}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "wb") as f:
            while True:
                chunk = await resp.content.read(CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
    return dest
