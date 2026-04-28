import pydantic
import pytest

from zinoargus.config.models import Configuration, FailoverConfiguration


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
