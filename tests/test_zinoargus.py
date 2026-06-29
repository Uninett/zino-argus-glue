import subprocess
import time
from datetime import datetime
from types import SimpleNamespace

import pytest

import zinoargus
from zinoargus import is_down_log, resolve_severity
from zinoargus.config.models import SeverityConfiguration


@pytest.mark.parametrize("log_message", ["linkDown", "lowerLayerDown", "up to down"])
def test_when_log_message_indicates_down_events_it_should_return_true(log_message):
    assert is_down_log(log_message)


class TestResolveSeverity:
    BANDS = [
        {"min_priority": 500, "level": 1},
        {"min_priority": 300, "level": 2},
        {"min_priority": 100, "level": 3},
        {"min_priority": 1, "level": 4},
    ]

    def _configure_severity(self, monkeypatch, severity):
        config = SimpleNamespace(sync=SimpleNamespace(severity=severity))
        monkeypatch.setattr(zinoargus, "_config", config)

    def test_when_priority_above_top_band_then_it_should_return_level_1(
        self, monkeypatch
    ):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=5, thresholds=self.BANDS)
        )
        assert resolve_severity(SimpleNamespace(priority=1000)) == 1

    def test_when_priority_in_mid_band_then_it_should_return_matching_level(
        self, monkeypatch
    ):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=5, thresholds=self.BANDS)
        )
        assert resolve_severity(SimpleNamespace(priority=350)) == 2

    def test_when_priority_equals_band_minimum_then_it_should_return_that_level(
        self, monkeypatch
    ):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=5, thresholds=self.BANDS)
        )
        assert resolve_severity(SimpleNamespace(priority=500)) == 1
        assert resolve_severity(SimpleNamespace(priority=100)) == 3

    def test_when_priority_below_lowest_band_then_it_should_return_default(
        self, monkeypatch
    ):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=5, thresholds=self.BANDS)
        )
        assert resolve_severity(SimpleNamespace(priority=0)) == 5

    def test_when_thresholds_empty_then_it_should_return_default(self, monkeypatch):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=2, thresholds=[])
        )
        assert resolve_severity(SimpleNamespace(priority=1000)) == 2

    def test_when_priority_not_an_int_then_it_should_return_default(self, monkeypatch):
        self._configure_severity(
            monkeypatch, SeverityConfiguration(default=4, thresholds=self.BANDS)
        )
        assert resolve_severity(SimpleNamespace(priority="bogus")) == 4


class TestCreateArgusIncident:
    def test_when_severity_configured_then_it_should_pass_resolved_level(
        self, monkeypatch
    ):
        config = SimpleNamespace(
            sync=SimpleNamespace(
                severity=SeverityConfiguration(
                    default=5, thresholds=[{"min_priority": 100, "level": 2}]
                )
            )
        )
        monkeypatch.setattr(zinoargus, "_config", config)
        monkeypatch.setattr(zinoargus, "describe_zino_case", lambda case: "down")
        monkeypatch.setattr(zinoargus, "generate_tags", lambda case: iter(()))
        monkeypatch.setattr(
            zinoargus, "synchronize_case_history", lambda case, inc: None
        )

        captured = {}

        def fake_post_incident(incident):
            captured["incident"] = incident
            return incident

        monkeypatch.setattr(
            zinoargus, "_argus", SimpleNamespace(post_incident=fake_post_incident)
        )

        case = SimpleNamespace(id=1, opened=datetime(2026, 1, 1), priority=200)
        zinoargus.create_argus_incident(case)

        assert captured["incident"].level == 2


@pytest.mark.slow
def test_zinoargus_should_not_crash_at_startup(zinoargus_external_run):
    delay = 3
    assert zinoargus_external_run.poll() is None, "zinoargus failed immediately"
    time.sleep(delay)
    assert zinoargus_external_run.poll() is None, (
        f"zinoargus failed within {delay} seconds"
    )


#
# Fixtures
#


@pytest.fixture
def zinoargus_external_run(zino, zinoargus_configuration_file):
    process = subprocess.Popen(["zinoargus", "-c", zinoargus_configuration_file])
    yield process
    process.terminate()


@pytest.fixture
def zinoargus_configuration_file(
    tmp_path, zino_test_user, argus_api_url, argus_source_system_token
):
    name = tmp_path / "zinoargus.toml"
    zino_user, zino_password = zino_test_user
    with open(name, "w") as conf:
        conf.write(
            f"""
            [argus]
            url = "{argus_api_url}"
            token = "{argus_source_system_token}"

            [zino]
            server = "localhost"
            port = 8001
            user = "{zino_user}"
            secret = "{zino_password}"
            """
        )
    yield name
