"""Tests for netbridge_agent.remote_exec HTTP handlers."""

import os

import pytest
from aiohttp.test_utils import TestClient

from netbridge_agent.remote_exec import create_app


@pytest.fixture
async def client(aiohttp_client):
    """Create a test client for the remote_exec app."""
    app = create_app()
    return await aiohttp_client(app)


# ---------------------------------------------------------------------------
# /health
# ---------------------------------------------------------------------------


class TestHealth:
    async def test_health_returns_200(self, client: TestClient):
        resp = await client.get("/health")
        assert resp.status == 200
        data = await resp.json()
        assert data["status"] == "ok"
        assert "hostname" in data
        assert "ip" in data
        assert "pid" in data
        assert data["pid"] == os.getpid()
        assert "cwd" in data


# ---------------------------------------------------------------------------
# /files?dir=<path>  (directory listing)
# ---------------------------------------------------------------------------


class TestFileList:
    async def test_list_existing_dir(self, client: TestClient, tmp_path):
        # Create some files
        (tmp_path / "alpha.txt").write_text("hello")
        (tmp_path / "beta").mkdir()
        (tmp_path / "gamma.log").write_text("world")

        resp = await client.get("/files", params={"dir": str(tmp_path)})
        assert resp.status == 200
        data = await resp.json()
        entries = data["entries"]
        names = [e["name"] for e in entries]
        # Should be sorted
        assert names == sorted(names)
        # Check structure
        for entry in entries:
            assert "name" in entry
            assert "is_dir" in entry
            assert "size" in entry
            assert "mtime" in entry
        # Verify specific entries
        alpha = next(e for e in entries if e["name"] == "alpha.txt")
        assert alpha["is_dir"] is False
        assert alpha["size"] == 5
        beta = next(e for e in entries if e["name"] == "beta")
        assert beta["is_dir"] is True

    async def test_list_nonexistent_dir(self, client: TestClient):
        resp = await client.get("/files", params={"dir": "/nonexistent_path_xyz"})
        assert resp.status == 404


# ---------------------------------------------------------------------------
# /files/{path}  (read / write / delete)
# ---------------------------------------------------------------------------


class TestFileReadWriteDelete:
    async def test_read_file(self, client: TestClient, tmp_path):
        f = tmp_path / "hello.txt"
        f.write_text("file content here")

        resp = await client.get(f"/files/{f}")
        assert resp.status == 200
        body = await resp.read()
        assert body == b"file content here"

    async def test_read_nonexistent(self, client: TestClient):
        resp = await client.get("/files/nonexistent_file_xyz_12345.txt")
        assert resp.status == 404

    async def test_write_file(self, client: TestClient, tmp_path):
        target = tmp_path / "output.txt"
        resp = await client.put(
            f"/files/{target}",
            data=b"new content",
        )
        assert resp.status == 200
        assert target.read_text() == "new content"

    async def test_write_creates_parent_dirs(self, client: TestClient, tmp_path):
        target = tmp_path / "sub" / "dir" / "deep.txt"
        resp = await client.put(
            f"/files/{target}",
            data=b"deep content",
        )
        assert resp.status == 200
        assert target.read_text() == "deep content"

    async def test_delete_file(self, client: TestClient, tmp_path):
        f = tmp_path / "deleteme.txt"
        f.write_text("bye")

        resp = await client.delete(f"/files/{f}")
        assert resp.status == 200
        assert not f.exists()

    async def test_delete_directory_recursive(self, client: TestClient, tmp_path):
        d = tmp_path / "mydir"
        d.mkdir()
        (d / "child.txt").write_text("x")
        (d / "sub").mkdir()
        (d / "sub" / "nested.txt").write_text("y")

        resp = await client.delete(f"/files/{d}")
        assert resp.status == 200
        assert not d.exists()

    async def test_delete_nonexistent(self, client: TestClient):
        resp = await client.delete("/files/nonexistent_path_xyz_12345")
        assert resp.status == 404


# ---------------------------------------------------------------------------
# /exec  (command execution)
# ---------------------------------------------------------------------------


class TestExec:
    async def test_simple_echo(self, client: TestClient):
        resp = await client.post("/exec", json={"cmd": "echo hello"})
        assert resp.status == 200
        data = await resp.json()
        assert data["exit_code"] == 0
        assert "hello" in data["stdout"]
        assert "stderr" in data

    async def test_missing_cmd(self, client: TestClient):
        resp = await client.post("/exec", json={"cwd": "/tmp"})
        assert resp.status == 400
        data = await resp.json()
        assert "error" in data

    async def test_invalid_json(self, client: TestClient):
        resp = await client.post(
            "/exec",
            data=b"not json{{{",
            headers={"Content-Type": "application/json"},
        )
        assert resp.status == 400
        data = await resp.json()
        assert "error" in data

    async def test_timeout(self, client: TestClient):
        resp = await client.post(
            "/exec",
            json={"cmd": "sleep 10", "timeout": 1},
        )
        assert resp.status == 504
        data = await resp.json()
        assert "timed out" in data["error"]


# ---------------------------------------------------------------------------
# /exec/stream  (streaming command execution)
# ---------------------------------------------------------------------------


class TestExecStream:
    async def test_simple_echo(self, client: TestClient):
        resp = await client.post("/exec/stream", json={"cmd": "echo hello_stream"})
        assert resp.status == 200
        body = (await resp.read()).decode()
        assert "hello_stream" in body
        assert "exit code:" in body.lower()

    async def test_missing_cmd(self, client: TestClient):
        resp = await client.post("/exec/stream", json={})
        assert resp.status == 400
        data = await resp.json()
        assert "error" in data
