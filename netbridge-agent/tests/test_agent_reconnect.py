"""Tests for agent reconnect logic, backoff, liveness and cleanup.

Covers run_agent's reconnect backoff escalation and reset, liveness timeout
detection, disconnect cleanup, and close_all_streams behavior.
"""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from netbridge_agent.agent import (
    AgentState,
    StreamInfo,
    close_all_streams,
    connect_and_run,
    run_agent,
    RECONNECT_DELAY,
    RECONNECT_BACKOFF_FACTOR,
    RECONNECT_DELAY_MAX,
    HEALTHY_CONNECTION_THRESHOLD,
)


class TestBackoffEscalation:
    """Reconnect backoff should escalate after short sessions."""

    @pytest.mark.asyncio
    async def test_backoff_escalates_for_short_sessions(self):
        """Short sessions should escalate backoff: [5, 10, 20, 40, 60, 60]."""
        delays = []
        call_count = 0
        stop = asyncio.Event()

        async def fake_connect_and_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count < 7:
                # Six short (1s) sessions
                return False, 1.0
            else:
                # Seventh call: stop
                stop.set()
                return True, 1.0

        async def capture_wait(coro, timeout):
            delays.append(timeout)
            if stop.is_set():
                coro.close()
                return
            coro.close()
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
             patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop)

        # After six short sessions, delays should escalate and cap at 60
        assert delays == [5, 10, 20, 40, 60, 60]

    @pytest.mark.asyncio
    async def test_backoff_resets_after_healthy_session(self):
        """Backoff resets after a session > HEALTHY_CONNECTION_THRESHOLD."""
        delays = []
        call_count = 0
        stop = asyncio.Event()
        sessions = [(False, 1.0), (False, 1.0), (False, 61.0), (False, 1.0)]

        async def fake_connect_and_run(*args, **kwargs):
            nonlocal call_count
            if call_count < len(sessions):
                result = sessions[call_count]
                call_count += 1
                return result
            else:
                stop.set()
                return True, 1.0

        async def capture_wait(coro, timeout):
            delays.append(timeout)
            if stop.is_set():
                coro.close()
                return
            coro.close()
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
             patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop)

        # After healthy 61s session, delay should reset back to RECONNECT_DELAY
        assert delays == [5, 10, 5, 10]

    @pytest.mark.asyncio
    async def test_handshake_failures_escalate(self):
        """Handshake failures (ClientError) should escalate backoff."""
        delays = []
        call_count = 0
        stop = asyncio.Event()

        async def fake_connect_and_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                raise aiohttp.ClientError("Connection refused")
            else:
                stop.set()
                return True, 1.0

        async def capture_wait(coro, timeout):
            delays.append(timeout)
            if stop.is_set():
                coro.close()
                return
            coro.close()
            raise asyncio.TimeoutError

        with patch("netbridge_agent.agent.connect_and_run", side_effect=fake_connect_and_run), \
             patch("netbridge_agent.agent.check_az_login", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_arm_token", return_value="tok"), \
             patch("netbridge_agent.agent.check_token_expiration", return_value=(True, "ok")), \
             patch("netbridge_agent.agent.get_user_identity", return_value="user@test"), \
             patch("netbridge_agent.agent.cleanup_idle_streams", new_callable=AsyncMock), \
             patch("netbridge_agent.agent.token_refresh_loop", new_callable=AsyncMock), \
             patch("asyncio.wait_for", side_effect=capture_wait):
            await run_agent("relay.com", stop)

        # After three handshake failures, delays should escalate
        assert delays == [5, 10, 20]


def _make_fake_websocket(msg_sequence):
    """Helper to create a fake websocket that returns a sequence of messages."""
    message_idx = [0]

    async def fake_receive():
        if message_idx[0] < len(msg_sequence):
            msg = msg_sequence[message_idx[0]]
            message_idx[0] += 1
            return msg
        raise asyncio.TimeoutError

    ws = MagicMock()
    ws.closed = False
    ws.receive = fake_receive
    ws.close = AsyncMock()
    ws.send_str = AsyncMock()

    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=ws)
    session.__aexit__ = AsyncMock()

    fake_client_session = MagicMock()
    fake_client_session.ws_connect = MagicMock(return_value=session)
    fake_client_session.__aenter__ = AsyncMock(return_value=fake_client_session)
    fake_client_session.__aexit__ = AsyncMock()

    return fake_client_session


class TestLivenessTimeout:
    """Liveness timeout detection should end the session."""

    @pytest.mark.asyncio
    async def test_liveness_timeout_ends_session(self, caplog):
        """When no messages arrive, session ends with 'assuming dead' log."""
        import logging
        caplog.set_level(logging.WARNING)

        stop = asyncio.Event()
        state = AgentState()

        messages = [
            MagicMock(type=aiohttp.WSMsgType.TEXT, data='{"type": "registered"}'),
        ]
        fake_client_session = _make_fake_websocket(messages)

        with patch("netbridge_agent.agent.aiohttp.ClientSession", return_value=fake_client_session), \
             patch("netbridge_agent.agent.CONNECTION_LIVENESS_TIMEOUT", 0.05), \
             patch("netbridge_agent.agent.close_all_streams", new_callable=AsyncMock):
            intentional, duration = await connect_and_run(
                state, "ws://relay.com", None, None, "token", stop, None, None
            )

        # Should not be intentional stop, should have a duration
        assert intentional is False
        assert duration > 0
        # Check log contains "assuming dead"
        assert any("assuming dead" in record.message for record in caplog.records)


class TestDisconnectCleanup:
    """Disconnect should trigger cleanup of streams and heartbeat task."""

    @pytest.mark.asyncio
    async def test_disconnect_closes_all_streams(self):
        """When websocket closes, close_all_streams and heartbeat cancellation happen."""
        stop = asyncio.Event()
        state = AgentState()
        heartbeat_task_holder = {}
        started = asyncio.Event()

        async def fake_heartbeat_sender(ws, stop_event, liveness_tracker):
            heartbeat_task_holder['task'] = asyncio.current_task()
            started.set()
            # Wait forever until cancelled
            await asyncio.Event().wait()

        # Delay the CLOSED message until heartbeat has started
        message_idx = [0]
        messages = [
            MagicMock(type=aiohttp.WSMsgType.TEXT, data='{"type": "registered"}'),
            MagicMock(type=aiohttp.WSMsgType.CLOSED),
        ]

        async def fake_receive():
            if message_idx[0] == 0:
                msg = messages[0]
                message_idx[0] += 1
                return msg
            elif message_idx[0] == 1:
                # Wait for heartbeat to start before returning CLOSED
                await started.wait()
                msg = messages[1]
                message_idx[0] += 1
                return msg
            raise asyncio.TimeoutError

        ws = MagicMock()
        ws.closed = False
        ws.receive = fake_receive
        ws.close = AsyncMock()
        ws.send_str = AsyncMock()

        session = MagicMock()
        session.__aenter__ = AsyncMock(return_value=ws)
        session.__aexit__ = AsyncMock()

        fake_client_session = MagicMock()
        fake_client_session.ws_connect = MagicMock(return_value=session)
        fake_client_session.__aenter__ = AsyncMock(return_value=fake_client_session)
        fake_client_session.__aexit__ = AsyncMock()

        with patch("netbridge_agent.agent.aiohttp.ClientSession", return_value=fake_client_session), \
             patch("netbridge_agent.agent.close_all_streams", new_callable=AsyncMock) as mock_close, \
             patch("netbridge_agent.agent.heartbeat_sender", new=fake_heartbeat_sender):
            await connect_and_run(
                state, "ws://relay.com", None, None, "token", stop, None, None
            )

        # close_all_streams should be called
        mock_close.assert_awaited_once_with(state)
        # Heartbeat task should be cancelled
        assert 'task' in heartbeat_task_holder
        assert heartbeat_task_holder['task'].cancelled()


class TestCloseAllStreams:
    """close_all_streams should close writers and cancel tasks."""

    @pytest.mark.asyncio
    async def test_close_all_streams_closes_targets_and_cancels_pending(self):
        """Verify close_all_streams closes writers and cancels pending tasks."""
        state = AgentState()

        # Create a fake writer
        writer = MagicMock()
        writer.close = MagicMock()
        writer.wait_closed = AsyncMock()

        # Create a fake forward task
        forward_task = asyncio.create_task(asyncio.sleep(10))

        # Create a stream
        stream = StreamInfo(
            reader=MagicMock(),
            writer=writer,
            forward_task=forward_task,
            host="example.com",
            port=80,
        )
        state.active_streams["s1"] = stream

        # Create a pending connection task
        pending_task = asyncio.create_task(asyncio.sleep(10))
        state.pending_connections["p1"] = pending_task

        # Close all streams
        await close_all_streams(state, timeout=1.0)

        # Verify writer was closed
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()

        # Verify tasks were cancelled
        assert forward_task.cancelled()
        assert pending_task.cancelled()

        # Verify state was cleared
        assert len(state.active_streams) == 0
        assert len(state.pending_connections) == 0
