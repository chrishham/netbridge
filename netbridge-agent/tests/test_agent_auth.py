"""Tests for run_agent's handling of relay auth rejections (401/403)."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from netbridge_agent.agent import run_agent


def _handshake_error(status: int) -> aiohttp.WSServerHandshakeError:
    return aiohttp.WSServerHandshakeError(
        request_info=MagicMock(), history=(), status=status, message="rejected",
    )


async def _run(outcomes, tokens=None):
    """Run the agent against a scripted sequence of connect outcomes.

    Each outcome is an exception to raise or a (intentional_stop, duration)
    tuple to return. Once the script runs out the agent is stopped.
    Returns (tokens passed to connect, status callback calls, get_arm_token mock).
    """
    stop = asyncio.Event()
    seen_tokens = []
    script = list(outcomes)

    async def fake_connect_and_run(state, relay_url, proxy, proxy_auth, token, *args):
        seen_tokens.append(token)
        if not script:
            stop.set()
            return True, 1.0
        outcome = script.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def no_wait(coro, timeout):
        coro.close()
        if stop.is_set():
            return
        raise asyncio.TimeoutError

    on_status = MagicMock()
    arm_token = MagicMock(side_effect=tokens or (f"tok{i}" for i in range(100)))
    with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
         patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
         patch("netbridge_agent.agent.get_arm_token", arm_token), \
         patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
         patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
         patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
         patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
         patch("asyncio.wait_for", side_effect=no_wait):
        await run_agent("relay.com", stop, on_status)
    return seen_tokens, on_status.call_args_list, arm_token


@pytest.mark.asyncio
async def test_401_refreshes_token_and_retries(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent")
    seen, _, arm_token = await _run([_handshake_error(401)])

    assert seen == ["tok0", "tok1"]
    assert arm_token.call_count == 2
    assert "Token refreshed after 401" in caplog.text
    assert "Max auth failures reached" not in caplog.text


@pytest.mark.asyncio
async def test_three_401s_give_up_even_though_refresh_succeeds(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent")
    seen, status_calls, _ = await _run([_handshake_error(401)] * 5)

    assert len(seen) == 3
    assert "Max auth failures reached" in caplog.text
    assert status_calls[-1].args == (False, True)


@pytest.mark.asyncio
async def test_successful_session_resets_auth_failures(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent")
    e401 = _handshake_error(401)
    seen, _, _ = await _run([e401, e401, (False, 5.0), e401, e401])

    assert len(seen) == 6
    assert "Max auth failures reached" not in caplog.text


@pytest.mark.asyncio
async def test_403_stops_without_retry(caplog):
    caplog.set_level(logging.INFO, logger="netbridge_agent")
    seen, status_calls, arm_token = await _run([_handshake_error(403)])

    assert len(seen) == 1
    assert arm_token.call_count == 1
    assert "Access forbidden" in caplog.text
    assert status_calls[-1].args == (False, True)
