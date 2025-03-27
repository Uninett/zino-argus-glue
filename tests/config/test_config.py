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
