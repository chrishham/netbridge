"""Tests for shared_auth.session — session ID generation, env helpers, and TokenHolder."""

from unittest.mock import MagicMock, patch

import pytest

from shared_auth.session import TokenHolder, get_int_env, get_session_id


# ---------------------------------------------------------------------------
# get_int_env
# ---------------------------------------------------------------------------
class TestGetIntEnv:
    """Tests for get_int_env()."""

    def test_present_valid(self, monkeypatch):
        """Returns parsed int when env var is a valid integer."""
        monkeypatch.setenv("TEST_INT_VAR", "42")
        assert get_int_env("TEST_INT_VAR", 10) == 42

    def test_present_invalid(self, monkeypatch):
        """Returns default when env var is not a valid integer."""
        monkeypatch.setenv("TEST_INT_VAR", "abc")
        assert get_int_env("TEST_INT_VAR", 10) == 10

    def test_missing(self, monkeypatch):
        """Returns default when env var is not set."""
        monkeypatch.delenv("TEST_INT_VAR", raising=False)
        assert get_int_env("TEST_INT_VAR", 10) == 10


# ---------------------------------------------------------------------------
# get_session_id
# ---------------------------------------------------------------------------
class TestGetSessionId:
    """Tests for get_session_id()."""

    @patch("shared_auth.session.getpass.getuser", return_value="testuser")
    @patch("shared_auth.session.socket.gethostname", return_value="testhost")
    def test_returns_16_char_hex(self, _mock_host, _mock_user):
        """Session ID is a 16-character hex string."""
        sid = get_session_id()
        assert len(sid) == 16
        int(sid, 16)  # should not raise

    @patch("shared_auth.session.getpass.getuser", return_value="testuser")
    @patch("shared_auth.session.socket.gethostname", return_value="testhost")
    def test_stable_across_calls(self, _mock_host, _mock_user):
        """Same hostname:username always produces the same session ID."""
        assert get_session_id() == get_session_id()

    @patch("shared_auth.session.getpass.getuser", return_value="other")
    @patch("shared_auth.session.socket.gethostname", return_value="testhost")
    def test_different_user_different_id(self, _mock_host, _mock_user):
        """Different username produces a different session ID."""
        id1 = get_session_id()

        with patch("shared_auth.session.getpass.getuser", return_value="alice"), \
             patch("shared_auth.session.socket.gethostname", return_value="testhost"):
            id2 = get_session_id()

        assert id1 != id2


# ---------------------------------------------------------------------------
# TokenHolder
# ---------------------------------------------------------------------------
class TestTokenHolder:
    """Tests for TokenHolder class."""

    def test_init_state(self):
        """Initial state stores token and has zero failures."""
        holder = TokenHolder("tok")
        assert holder.get() == "tok"
        assert holder.failure_count == 0

    def test_init_none_token(self):
        """Can be initialized with None token."""
        holder = TokenHolder(None)
        assert holder.get() is None

    def test_get(self):
        """get() returns the current token."""
        holder = TokenHolder("abc")
        assert holder.get() == "abc"

    def test_refresh_success(self):
        """Successful refresh updates the token and resets failure_count."""
        callback = MagicMock(return_value="new_tok")
        holder = TokenHolder("old", refresh_callback=callback)
        holder.failure_count = 2

        result = holder.refresh()

        assert result is True
        assert holder.get() == "new_tok"
        assert holder.failure_count == 0
        callback.assert_called_once()

    def test_refresh_callback_returns_none(self):
        """Callback returning None does not update token."""
        callback = MagicMock(return_value=None)
        holder = TokenHolder("old", refresh_callback=callback)

        result = holder.refresh()

        assert result is False
        assert holder.get() == "old"

    def test_refresh_callback_raises(self):
        """RuntimeError from callback increments failure_count."""
        callback = MagicMock(side_effect=RuntimeError("auth error"))
        holder = TokenHolder("old", refresh_callback=callback)

        result = holder.refresh()

        assert result is False
        assert holder.failure_count == 1
        assert holder.get() == "old"

    def test_refresh_no_callback(self):
        """Refresh returns False when no callback is set."""
        holder = TokenHolder("tok")
        assert holder.refresh() is False

    def test_failure_count_accumulates(self):
        """Multiple failures increment the counter."""
        callback = MagicMock(side_effect=RuntimeError("fail"))
        holder = TokenHolder("tok", refresh_callback=callback)

        holder.refresh()
        holder.refresh()
        holder.refresh()

        assert holder.failure_count == 3
