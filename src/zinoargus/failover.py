"""Failover state machine for primary/secondary Zino deployments."""

import logging
from enum import Enum

from zinoargus.zping import ZpingError, get_zino_uptime

_logger = logging.getLogger(__name__)


class Mode(Enum):
    STANDBY = "standby"
    ACTIVE = "active"


class InstanceState:
    """Tracks whether this instance should actively sync to Argus.

    When no failover configuration is provided, the instance is always ACTIVE
    (primary mode). When configured, starts in STANDBY and switches to ACTIVE
    after ``threshold`` consecutive ping failures to the primary, then back to
    STANDBY after ``threshold`` consecutive successes.
    """

    def __init__(self, config=None):
        self._config = config
        if config is None:
            self._mode = Mode.ACTIVE
        else:
            self._mode = Mode.STANDBY
        self._consecutive_failures = 0
        self._consecutive_successes = 0

    @property
    def mode(self) -> Mode:
        return self._mode

    @property
    def is_active(self) -> bool:
        return self._mode is Mode.ACTIVE

    def ping(self) -> None:
        """Ping the primary Zino and update failover state.

        No-op when running in primary mode (no failover config).
        """
        if self._config is None:
            return

        try:
            uptime = get_zino_uptime(
                host=str(self._config.primary_server),
                port=self._config.primary_snmp_port,
                community=self._config.snmp_community,
                timeout=self._config.ping_timeout,
            )
        except ZpingError as exc:
            self._on_failure()
            _logger.warning(
                "Zino primary ping failed for %s: %s (%s consecutive)",
                self._config.primary_server,
                exc,
                self._consecutive_failures,
            )
        else:
            self._on_success()
            _logger.debug(
                "Zino primary ping OK for %s, uptime: %s (%s consecutive)",
                self._config.primary_server,
                uptime,
                self._consecutive_successes,
            )

    def _on_success(self) -> None:
        self._consecutive_successes += 1
        self._consecutive_failures = 0

        if (
            self._mode is Mode.ACTIVE
            and self._consecutive_successes >= self._config.threshold
        ):
            _logger.info(
                "Primary is back (%s consecutive successes), switching to STANDBY",
                self._consecutive_successes,
            )
            self._mode = Mode.STANDBY
            self._reset_counters()

    def _on_failure(self) -> None:
        self._consecutive_failures += 1
        self._consecutive_successes = 0

        if (
            self._mode is Mode.STANDBY
            and self._consecutive_failures >= self._config.threshold
        ):
            _logger.warning(
                "Primary unreachable (%s consecutive failures), switching to ACTIVE",
                self._consecutive_failures,
            )
            self._mode = Mode.ACTIVE
            self._reset_counters()

    def _reset_counters(self) -> None:
        self._consecutive_failures = 0
        self._consecutive_successes = 0
