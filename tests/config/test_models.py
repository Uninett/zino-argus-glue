import pydantic
import pytest

from zinoargus.config.models import (
    Configuration,
    FailoverConfiguration,
    SeverityConfiguration,
)


def test_when_configuration_is_empty_it_should_not_validate():
    with pytest.raises(pydantic.ValidationError):
        Configuration()


class TestFailoverConfiguration:
    def test_when_only_primary_server_given_it_should_validate(self):
        config = FailoverConfiguration(primary_server="10.0.0.1")
        assert str(config.primary_server) == "10.0.0.1"
        assert config.primary_snmp_port == 8000
        assert config.snmp_community == "public"
        assert config.ping_timeout == 5
        assert config.threshold == 10

    def test_when_primary_server_missing_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            FailoverConfiguration()

    def test_when_extra_field_given_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            FailoverConfiguration(primary_server="10.0.0.1", bogus="value")


class TestConfigurationFailover:
    def test_when_failover_absent_it_should_be_none(self):
        config = Configuration(
            argus={"url": "https://argus.example.org/api/v2", "token": "secret"},
            zino={
                "server": "zino.example.org",
                "user": "zinouser",
                "secret": "secret",
            },
        )
        assert config.failover is None


class TestConfigurationSeverity:
    def test_when_severity_absent_it_should_default_to_level_3(self):
        config = Configuration(
            argus={"url": "https://argus.example.org/api/v2", "token": "secret"},
            zino={
                "server": "zino.example.org",
                "user": "zinouser",
                "secret": "secret",
            },
        )
        assert config.sync.severity is not None
        assert config.sync.severity.default == 3
        assert config.sync.severity.thresholds == []


class TestSeverityConfiguration:
    def test_when_valid_block_given_it_should_validate(self):
        config = SeverityConfiguration(
            default=4,
            thresholds=[
                {"min_priority": 500, "level": 1},
                {"min_priority": 100, "level": 3},
            ],
        )
        assert config.default == 4
        assert config.thresholds[0].min_priority == 500
        assert config.thresholds[0].level == 1
        assert config.thresholds[1].min_priority == 100
        assert config.thresholds[1].level == 3

    def test_when_block_is_empty_it_should_use_defaults(self):
        config = SeverityConfiguration()
        assert config.default == 3
        assert config.thresholds == []

    def test_when_default_out_of_range_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            SeverityConfiguration(default=6)

    def test_when_level_out_of_range_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            SeverityConfiguration(thresholds=[{"min_priority": 100, "level": 0}])

    def test_when_min_priority_negative_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            SeverityConfiguration(thresholds=[{"min_priority": -1, "level": 1}])

    def test_when_extra_field_given_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            SeverityConfiguration(bogus="value")

    def test_when_band_has_extra_field_it_should_not_validate(self):
        with pytest.raises(pydantic.ValidationError):
            SeverityConfiguration(
                thresholds=[{"min_priority": 100, "level": 1, "bogus": "value"}]
            )
