import pytest

from zinoargus.config import InvalidConfigurationError, read_configuration
from zinoargus.config.models import Configuration


class TestReadValidConfiguration:
    def test_it_should_return_a_configuration_model(self, valid_configuration_file):
        config = read_configuration(valid_configuration_file)
        assert isinstance(config, Configuration)

    def test_it_should_return_a_configuration_model_with_corrent_argus_url(
        self, valid_configuration_file
    ):
        config = read_configuration(valid_configuration_file)
        assert str(config.argus.url) == "https://argus.example.org/api/v2"


def test_when_configuration_file_is_invalid_toml_it_should_raise_invalid_configuration_error(
    syntax_error_configuration_file,
):
    with pytest.raises(InvalidConfigurationError):
        read_configuration(syntax_error_configuration_file)


def test_when_configuration_file_has_invalid_value_it_should_raise_invalid_configuration_error(
    invalid_value_configuration_file,
):
    with pytest.raises(InvalidConfigurationError):
        read_configuration(invalid_value_configuration_file)


class TestReadConfigurationWithFailover:
    def test_when_failover_section_present_it_should_parse_correctly(
        self, failover_configuration_file
    ):
        config = read_configuration(failover_configuration_file)
        assert config.failover is not None
        assert str(config.failover.primary_server) == "10.0.0.1"
        assert config.failover.primary_snmp_port == 8000
        assert config.failover.threshold == 5

    def test_when_failover_section_absent_it_should_be_none(
        self, valid_configuration_file
    ):
        config = read_configuration(valid_configuration_file)
        assert config.failover is None


@pytest.fixture
def failover_configuration_file(tmp_path):
    name = tmp_path / "zinoargus.toml"
    with open(name, "w") as conf:
        conf.write(
            """[argus]
            url = "https://argus.example.org/api/v2"
            token = "secret"

            [zino]
            server = "zino.example.org"
            port = 8001
            user = "zinouser"
            secret = "secret"

            [failover]
            primary_server = "10.0.0.1"
            primary_snmp_port = 8000
            threshold = 5
            """
        )
    yield name


@pytest.fixture
def valid_configuration_file(tmp_path):
    name = tmp_path / "zinoargus.toml"
    with open(name, "w") as conf:
        conf.write(
            """[argus]
            url = "https://argus.example.org/api/v2"
            token = "secret"

            [zino]
            server = "zino.example.org"
            port = 8001
            user = "zinouser"
            secret = "secret"
            """
        )
    yield name


@pytest.fixture
def syntax_error_configuration_file(tmp_path):
    name = tmp_path / "zinoargus.toml"
    with open(name, "w") as conf:
        conf.write(
            """[argus
            url = "https://argus.example.org/api/v2
            """
        )
    yield name


@pytest.fixture
def invalid_value_configuration_file(tmp_path):
    name = tmp_path / "zinoargus.toml"
    with open(name, "w") as conf:
        conf.write(
            """[argus]
            url = "https://argus.example.org/api/v2"
            token = "secret"

            [zino]
            server = "zino.example.org"
            port = "badportvalue"
            user = "zinouser"
            secret = "secret"
            """
        )
    yield name
