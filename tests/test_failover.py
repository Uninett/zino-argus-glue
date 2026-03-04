from unittest.mock import MagicMock, patch

from zinoargus.failover import InstanceState, Mode
from zinoargus.zping import ZpingError


def _make_config(threshold=3):
    config = MagicMock()
    config.primary_server = "10.0.0.1"
    config.primary_snmp_port = 8000
    config.snmp_community = "public"
    config.ping_timeout = 5
    config.threshold = threshold
    return config


class TestInstanceStateWithoutConfig:
    def test_when_no_config_it_should_always_be_active(self):
        state = InstanceState(None)
        assert state.is_active
        assert state.mode is Mode.ACTIVE

    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_no_config_ping_should_be_noop(self, mock_uptime):
        state = InstanceState(None)
        state.ping()
        mock_uptime.assert_not_called()
        assert state.is_active


class TestInstanceStateStandbyToActive:
    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_configured_it_should_start_in_standby(self, mock_uptime):
        state = InstanceState(_make_config())
        assert not state.is_active
        assert state.mode is Mode.STANDBY

    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_threshold_failures_reached_it_should_switch_to_active(
        self, mock_uptime
    ):
        mock_uptime.side_effect = ZpingError("unreachable")
        state = InstanceState(_make_config(threshold=3))

        for _ in range(3):
            state.ping()

        assert state.is_active
        assert state.mode is Mode.ACTIVE

    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_fewer_than_threshold_failures_it_should_stay_in_standby(
        self, mock_uptime
    ):
        mock_uptime.side_effect = ZpingError("unreachable")
        state = InstanceState(_make_config(threshold=3))

        for _ in range(2):
            state.ping()

        assert not state.is_active

    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_success_interrupts_failures_it_should_reset_counter(
        self, mock_uptime
    ):
        config = _make_config(threshold=3)
        state = InstanceState(config)

        mock_uptime.side_effect = ZpingError("unreachable")
        state.ping()  # fail 1
        state.ping()  # fail 2

        mock_uptime.side_effect = None
        mock_uptime.return_value = 100
        state.ping()  # success resets counter

        mock_uptime.side_effect = ZpingError("unreachable")
        state.ping()  # fail 1 again
        state.ping()  # fail 2 again

        assert not state.is_active


class TestInstanceStateActiveToStandby:
    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_threshold_successes_reached_it_should_switch_to_standby(
        self, mock_uptime
    ):
        mock_uptime.side_effect = ZpingError("unreachable")
        config = _make_config(threshold=3)
        state = InstanceState(config)

        # First get to ACTIVE
        for _ in range(3):
            state.ping()
        assert state.is_active

        # Now succeed threshold times
        mock_uptime.side_effect = None
        mock_uptime.return_value = 100
        for _ in range(3):
            state.ping()

        assert not state.is_active
        assert state.mode is Mode.STANDBY

    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_failure_interrupts_successes_it_should_reset_counter(
        self, mock_uptime
    ):
        mock_uptime.side_effect = ZpingError("unreachable")
        config = _make_config(threshold=3)
        state = InstanceState(config)

        # Get to ACTIVE
        for _ in range(3):
            state.ping()
        assert state.is_active

        # Two successes then a failure
        mock_uptime.side_effect = None
        mock_uptime.return_value = 100
        state.ping()
        state.ping()

        mock_uptime.side_effect = ZpingError("unreachable")
        state.ping()  # resets success counter

        mock_uptime.side_effect = None
        mock_uptime.return_value = 100
        state.ping()
        state.ping()

        # Still active (only 2 consecutive successes)
        assert state.is_active


class TestInstanceStateCounterResetOnTransition:
    @patch("zinoargus.failover.get_zino_uptime")
    def test_when_transitioning_to_active_counters_should_reset(self, mock_uptime):
        mock_uptime.side_effect = ZpingError("unreachable")
        config = _make_config(threshold=3)
        state = InstanceState(config)

        # Transition to ACTIVE
        for _ in range(3):
            state.ping()
        assert state.is_active

        # Counters reset, so one more failure should NOT trigger anything weird
        state.ping()
        # Need full threshold of successes to go back
        mock_uptime.side_effect = None
        mock_uptime.return_value = 100
        state.ping()
        state.ping()
        assert state.is_active  # only 2 successes, counter was reset
