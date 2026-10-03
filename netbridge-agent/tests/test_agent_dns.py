import asyncio
import ipaddress
import json
import socket
from unittest.mock import AsyncMock, MagicMock

import pytest

from netbridge_agent import agent
from netbridge_agent.agent import AgentState, DnsError, handle_message, resolve_destination


def _ws():
    ws = MagicMock(closed=False)
    ws.send_str = AsyncMock()
    return ws


def _results(ws):
    return [json.loads(c.args[0]) for c in ws.send_str.await_args_list]


def _infos(*addrs):
    return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, 0)) for a in addrs]


def _connect(stream_id, host, port=80):
    return json.dumps({"type": "tcp_connect", "stream_id": stream_id, "host": host, "port": port})


async def test_resolution_is_single_and_connect_uses_validated_ip(monkeypatch):
    answers = [_infos("1.2.3.4"), _infos("127.0.0.1")]       # a rebinding resolver
    calls = []

    async def fake_getaddrinfo(self, host, port, **kw):
        calls.append(kw)
        return answers[len(calls) - 1]

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake_getaddrinfo)
    opened = []

    async def fake_open(host, port):
        opened.append(host)
        return MagicMock(), MagicMock(close=MagicMock(), wait_closed=AsyncMock(), get_extra_info=lambda *_: None)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, _connect("s1", "rebind.test"))
    await asyncio.gather(*state.pending_connections.values())
    assert len(calls) == 1 and calls[0]["type"] == socket.SOCK_STREAM
    assert opened == ["1.2.3.4"]                              # never the second answer


async def test_one_blocked_address_among_several_rejects(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("8.8.8.8", "169.254.169.254")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, _connect("s1", "x.test"))
    await asyncio.gather(*state.pending_connections.values())
    (res,) = _results(ws)
    assert res["success"] is False and "not allowed" in res["error"]


async def test_resolver_answering_mapped_loopback_is_denied(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("::ffff:127.0.0.1")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    assert (await agent.validate_destination("m.test", 80))[0] is False


async def test_validate_destination_treats_dns_failure_as_no_addresses(monkeypatch):
    async def fake(self, host, port, **kw):
        raise socket.gaierror("nope")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    assert await agent.validate_destination("n.test", 80) == (True, "")
    ok, err = await agent.validate_destination("n.test", 80, denied_destinations=["n.test"])
    assert ok is False and "denied" in err


async def test_resolve_literal_skips_dns_and_wraps_errors(monkeypatch):
    assert await resolve_destination("[::ffff:1.2.3.4]", 80) == [ipaddress.ip_address("1.2.3.4")]

    async def boom(self, host, port, **kw):
        raise socket.gaierror(-2, "Name or service not known")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", boom)
    with pytest.raises(DnsError, match="Name or service not known"):
        await resolve_destination("bad.test", 80)


async def test_select_filters_by_allowlist_and_denies_when_none_pass():
    ips = [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("1.1.1.1")]
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, allowed_destinations=["8.8.8.0/24"])
    assert err == "" and got == [ipaddress.ip_address("8.8.8.8")]          # 1.1.1.1 is dropped, not dialled
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, allowed_destinations=["9.9.9.0/24"])
    assert got == [] and "not in the allowed destinations list" in err
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, denied_destinations=["8.8.8.0/24"])
    assert err == "" and got == [ipaddress.ip_address("1.1.1.1")]
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, allowed_destinations=["x.test"])
    assert got == ips                                                      # hostname-pattern allow passes all
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, denied_destinations=["8.8.8.0/24", "1.1.1.0/24"])
    assert got == [] and "is denied (matches" in err
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, denied_destinations=["x.test"])
    assert got == [] and err == "Destination x.test is denied"


async def test_select_denies_everything_when_any_address_is_always_blocked():
    ips = [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("169.254.169.254")]
    got, err = await agent.select_destinations("x.test", 80, resolved=ips, allowed_destinations=["8.8.8.0/24"])
    assert got == [] and "blocked range" in err


async def test_mixed_allowlist_answer_only_dials_the_allowed_ip_even_when_it_fails(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("1.1.1.1", "8.8.8.8")                 # the disallowed address comes first
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    opened = []

    async def fake_open(host, port):
        opened.append(host)
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    state, ws = AgentState(), _ws()
    state.allowed_destinations = ["8.8.8.0/24"]
    await handle_message(state, ws, _connect("s1", "mix.test"))
    await asyncio.gather(*state.pending_connections.values())
    assert opened == ["8.8.8.8"]                              # 1.1.1.1 never dialled, not even as a fallback
    (res,) = _results(ws)
    assert res["success"] is False and "refused" in res["error"]


async def test_dns_timeout_is_bounded_and_reported(monkeypatch):
    async def never(self, host, port, **kw):
        await asyncio.Event().wait()
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", never)
    monkeypatch.setattr(agent, "DNS_TIMEOUT", 0.01)
    with pytest.raises(DnsError, match="DNS resolution timed out for slow.test"):
        await resolve_destination("slow.test", 80)           # no timeout argument: uses the patched DNS_TIMEOUT
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, _connect("s1", "slow.test"))
    await asyncio.wait_for(asyncio.gather(*state.pending_connections.values()), 2)
    (res,) = _results(ws)
    assert res["success"] is False and "timed out" in res["error"]


async def test_addresses_are_deduplicated_in_order(monkeypatch):
    async def fake(self, host, port, **kw):
        return _infos("1.1.1.1", "2.2.2.2", "1.1.1.1")
    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", fake)
    assert [str(a) for a in await resolve_destination("d.test", 80)] == ["1.1.1.1", "2.2.2.2"]


async def test_connect_falls_back_to_the_next_validated_address(monkeypatch):
    tried = []

    async def fake_open(host, port):
        tried.append(host)
        if host == "1.1.1.1":
            raise ConnectionRefusedError("refused")
        return MagicMock(), MagicMock(get_extra_info=lambda *_: None)

    monkeypatch.setattr(asyncio, "open_connection", fake_open)
    addrs = [ipaddress.ip_address("1.1.1.1"), ipaddress.ip_address("2.2.2.2")]
    await agent.open_tcp_connection("h.test", 80, addresses=addrs)
    assert tried == ["1.1.1.1", "2.2.2.2"]
    monkeypatch.setattr(asyncio, "open_connection", AsyncMock(side_effect=ConnectionRefusedError("last")))
    with pytest.raises(ConnectionRefusedError, match="last"):
        await agent.open_tcp_connection("h.test", 80, addresses=addrs)
    with pytest.raises(asyncio.TimeoutError):                 # deadline already spent
        await agent.open_tcp_connection("h.test", 80, timeout=0, addresses=addrs)


async def test_dns_pending_does_not_block_other_streams(monkeypatch, mock_writer, mock_reader):
    gate = asyncio.Event()

    async def blocked(self, host, port, **kw):
        await gate.wait()
        return _infos("8.8.8.8")

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", blocked)
    state, ws = AgentState(), _ws()
    state.active_streams["B"] = agent.StreamInfo(mock_reader, mock_writer, None, "b", 80)
    await handle_message(state, ws, _connect("A", "slow.test"))
    await asyncio.wait_for(handle_message(state, ws, json.dumps({"type": "tcp_data", "stream_id": "B", "data": "AA=="})), 1)
    mock_writer.write.assert_called_once_with(b"\x00")
    await asyncio.wait_for(handle_message(state, ws, json.dumps({"type": "tcp_close", "stream_id": "B"})), 1)
    assert "B" not in state.active_streams and "A" in state.pending_connections
    task = state.pending_connections["A"]
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert state.pending_connections == {}


async def test_tcp_close_cancels_pending_dns_and_no_stream_appears(monkeypatch):
    gate, opened = asyncio.Event(), []

    async def blocked(self, host, port, **kw):
        await gate.wait()
        return _infos("8.8.8.8")

    monkeypatch.setattr(asyncio.get_running_loop().__class__, "getaddrinfo", blocked)
    monkeypatch.setattr(asyncio, "open_connection", lambda *a, **k: opened.append(a))
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, _connect("A", "slow.test"))
    task = state.pending_connections["A"]
    await asyncio.sleep(0)                                    # let the task reach the gate
    await handle_message(state, ws, json.dumps({"type": "tcp_close", "stream_id": "A"}))
    assert task.cancelled()
    gate.set()
    await asyncio.sleep(0)
    assert opened == [] and state.active_streams == {} and state.pending_connections == {}
    ws.send_str.assert_not_awaited()


async def test_cancel_between_connect_and_registration_closes_the_writer(monkeypatch):
    writer = MagicMock(close=MagicMock(), wait_closed=AsyncMock(), get_extra_info=lambda *_: None)

    async def fake_open(*a, **k):
        return MagicMock(), writer

    monkeypatch.setattr(agent, "open_tcp_connection", fake_open)
    state, ws = AgentState(), _ws()
    await handle_message(state, ws, _connect("A", "8.8.8.8"))
    task = state.pending_connections["A"]
    async with state.get_lock():                              # registration will block on this lock
        for _ in range(10):                                   # task connects, then waits for the lock
            await asyncio.sleep(0)
        assert not task.done()
        task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    assert task.cancelled()
    writer.close.assert_called()
    assert state.active_streams == {} and state.pending_connections == {}
