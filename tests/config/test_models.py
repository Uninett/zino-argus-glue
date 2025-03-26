import pydantic
import pytest

from zinoargus.config.models import Configuration


def test_when_configuration_is_empty_it_should_not_validate():
    with pytest.raises(pydantic.ValidationError):
        Configuration()
