"""Unit tests for the daemon's robustness machinery: the supervisor reconnect
loop, the Argus retry helper, the per-operation boundary guards, and the
best-effort circuit-metadata fetch.
"""

from datetime import timedelta
from unittest.mock import MagicMock, patch

import pytest
import zinolib as ritz
from simple_rest_client.exceptions import (
    AuthError,
    ClientConnectionError,
    NotFoundError,
    ServerError,
)
from zinolib.ritz import NotifierResponse

import zinoargus


def _server_error(message="boom"):
    return ServerError(message=message, response=MagicMock())


def _auth_error(message="bad token"):
    return AuthError(message=message, response=MagicMock())


def _not_found_error(message="gone"):
    return NotFoundError(message=message, response=MagicMock())


def _make_config():
    """A config mock covering the attributes the refresh path reads."""
    config = MagicMock()
    config.sync.acknowledge.setstate = "none"
    config.sync.ticket.enable = False
    return config


@patch("zinoargus.time.sleep")
class TestCallArgus:
    def test_when_operation_succeeds_then_it_should_return_the_result(self, _sleep):
        operation = MagicMock(return_value="result")
        assert zinoargus.call_argus(operation, 1, kw=2) == "result"
        operation.assert_called_once_with(1, kw=2)

    def test_when_a_transient_error_clears_then_it_should_retry(self, _sleep):
        operation = MagicMock(side_effect=[_server_error(), "result"])
        assert zinoargus.call_argus(operation) == "result"
        assert operation.call_count == 2

    def test_when_a_connection_error_clears_then_it_should_retry(self, _sleep):
        operation = MagicMock(side_effect=[ClientConnectionError("net"), "result"])
        assert zinoargus.call_argus(operation) == "result"
        assert operation.call_count == 2

    def test_when_auth_error_then_it_should_not_retry(self, _sleep):
        operation = MagicMock(side_effect=_auth_error())
        with pytest.raises(AuthError):
            zinoargus.call_argus(operation)
        operation.assert_called_once()

    def test_when_client_error_then_it_should_not_retry(self, _sleep):
        # A 4xx such as 404 won't fix itself, so it propagates without retrying.
        operation = MagicMock(side_effect=_not_found_error())
        with pytest.raises(NotFoundError):
            zinoargus.call_argus(operation)
        operation.assert_called_once()

    def test_when_transient_errors_exhaust_attempts_then_it_should_reraise(
        self, _sleep
    ):
        operation = MagicMock(side_effect=_server_error())
        with pytest.raises(ServerError):
            zinoargus.call_argus(operation)
        assert operation.call_count == zinoargus.ARGUS_RETRY_ATTEMPTS


@patch("zinoargus.time.sleep")
@patch("zinoargus.start")
@patch("zinoargus.connect_to_zino")
class TestRunSupervised:
    def test_when_connect_fails_once_then_it_should_reconnect_and_continue(
        self, connect, start, sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        connect.side_effect = [
            ritz.NotConnectedError("down"),
            (MagicMock(), MagicMock()),
        ]
        # The second, successful connection runs start(), which we make exit cleanly.
        start.side_effect = SystemExit()

        zinoargus.run_supervised()

        assert connect.call_count == 2
        start.assert_called_once()
        sleep.assert_called()  # backed off between the failed and the retried connect

    def test_when_zino_authentication_fails_then_it_should_exit_without_retry(
        self, connect, start, sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        connect.side_effect = ritz.AuthenticationError("nope")

        zinoargus.run_supervised()

        connect.assert_called_once()
        sleep.assert_not_called()

    def test_when_argus_authentication_fails_then_it_should_exit_without_retry(
        self, connect, start, sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        connect.return_value = (MagicMock(), MagicMock())
        start.side_effect = _auth_error()

        zinoargus.run_supervised()

        start.assert_called_once()
        sleep.assert_not_called()

    def test_when_sessions_are_short_lived_then_it_should_grow_the_backoff(
        self, connect, start, sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        # A reset threshold far in the future means no session counts as healthy.
        monkeypatch.setattr(zinoargus, "RECONNECT_RESET_AFTER", timedelta(days=1))
        connect.return_value = (MagicMock(), MagicMock())
        start.side_effect = [_server_error(), _server_error(), SystemExit()]

        zinoargus.run_supervised()

        delays = [call.args[0] for call in sleep.call_args_list]
        assert delays == [
            zinoargus.RECONNECT_BACKOFF_BASE.total_seconds(),
            (
                zinoargus.RECONNECT_BACKOFF_BASE * zinoargus.RECONNECT_BACKOFF_FACTOR
            ).total_seconds(),
        ]

    def test_when_session_was_healthy_then_it_should_reset_the_backoff(
        self, connect, start, sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        # A negative threshold means every session counts as healthy, so the
        # backoff resets to base before each reconnect.
        monkeypatch.setattr(zinoargus, "RECONNECT_RESET_AFTER", timedelta(seconds=-1))
        connect.return_value = (MagicMock(), MagicMock())
        start.side_effect = [_server_error(), _server_error(), SystemExit()]

        zinoargus.run_supervised()

        base = zinoargus.RECONNECT_BACKOFF_BASE.total_seconds()
        delays = [call.args[0] for call in sleep.call_args_list]
        assert delays == [base, base]


class TestRefreshArgusIncidents:
    def _incident(self, pk, **kwargs):
        incident = MagicMock()
        incident.pk = pk
        incident.acked = kwargs.get("acked", False)
        incident.open = kwargs.get("open", True)
        return incident

    @patch("zinoargus.time.sleep")
    def test_when_one_incident_is_transiently_unavailable_then_it_should_skip_and_continue(
        self, _sleep, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        argus = MagicMock()

        def get_incident(pk):
            if pk == 1:
                raise _server_error()
            return self._incident(pk)

        argus.get_incident.side_effect = get_incident
        monkeypatch.setattr(zinoargus, "_argus", argus)

        argus_incidents = {10: self._incident(1), 20: self._incident(2)}
        zino_cases = {10: MagicMock(), 20: MagicMock()}

        zinoargus.refresh_argus_incidents(argus_incidents, zino_cases)

        # Case 10 (pk 1) is skipped, but case 20 (pk 2) is refreshed.
        assert argus_incidents[10].pk == 1  # untouched original
        assert argus_incidents[20].pk == 2  # replaced with the fetched incident

    def test_when_an_incident_returns_not_found_then_it_should_skip_and_continue(
        self, monkeypatch
    ):
        # A 404 (incident deleted server-side) must be skipped in place, not allowed
        # to escape and trigger a Zino reconnect.
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        argus = MagicMock()

        def get_incident(pk):
            if pk == 1:
                raise _not_found_error()
            return self._incident(pk)

        argus.get_incident.side_effect = get_incident
        monkeypatch.setattr(zinoargus, "_argus", argus)

        argus_incidents = {10: self._incident(1), 20: self._incident(2)}
        zino_cases = {10: MagicMock(), 20: MagicMock()}

        zinoargus.refresh_argus_incidents(argus_incidents, zino_cases)

        assert argus_incidents[10].pk == 1  # skipped, untouched
        assert argus_incidents[20].pk == 2  # still refreshed

    def test_when_an_incident_refresh_raises_auth_error_then_it_should_propagate(
        self, monkeypatch
    ):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        argus = MagicMock()
        argus.get_incident.side_effect = _auth_error()
        monkeypatch.setattr(zinoargus, "_argus", argus)

        argus_incidents = {10: self._incident(1)}
        zino_cases = {10: MagicMock()}

        with pytest.raises(AuthError):
            zinoargus.refresh_argus_incidents(argus_incidents, zino_cases)


class TestSynchronizeContinuously:
    """Exercises a single guarded iteration of the event loop.

    The loop runs forever, so each test makes the *second* notifier poll raise
    ``SystemExit`` to break out once the behaviour under test has occurred.
    """

    def _setup(self, monkeypatch, poll_side_effect):
        monkeypatch.setattr(zinoargus, "_config", _make_config())
        notifier = MagicMock()
        notifier.poll.side_effect = poll_side_effect
        monkeypatch.setattr(zinoargus, "_notifier", notifier)
        monkeypatch.setattr(zinoargus, "_zino", MagicMock())
        monkeypatch.setattr(zinoargus, "_argus", MagicMock())
        instance = MagicMock()
        instance.is_active = True
        return instance

    def test_when_argus_processing_raises_transient_error_then_the_loop_should_continue(
        self, monkeypatch
    ):
        update = NotifierResponse(id=42, type="state", info="open down")
        instance = self._setup(monkeypatch, [update, SystemExit()])
        monkeypatch.setattr(zinoargus, "is_case_interesting", lambda case: True)
        monkeypatch.setattr(
            zinoargus,
            "get_or_make_argus_incident_for_zino_case",
            MagicMock(side_effect=_server_error()),
        )

        # Reaching the second poll (SystemExit) proves the transient error on the
        # first update was swallowed and the loop kept going.
        with pytest.raises(SystemExit):
            zinoargus.synchronize_continuously({}, {}, instance)

    def test_when_zino_connection_drops_then_the_error_should_propagate(
        self, monkeypatch
    ):
        update = NotifierResponse(id=42, type="state", info="open down")
        instance = self._setup(monkeypatch, [update])
        # Fetching the case details hits Zino and must not be swallowed.
        zinoargus._zino.case.side_effect = ritz.NotConnectedError("down")

        with pytest.raises(ritz.NotConnectedError):
            zinoargus.synchronize_continuously({}, {}, instance)
