from os import PathLike
from typing import Union

try:
    from tomllib import TOMLDecodeError, load
except ImportError:
    from tomli import TOMLDecodeError, load


def read_configuration(config_file_name: Union[str, PathLike[str]]) -> dict:
    """Reads and returns the configuration file contents as a dictionary.

    Returns configuration if file name is given and file exists.

    Raises `InvalidConfigurationError` if TOML file is invalid, OSError if the config
    TOML file could not be found.
    """
    with open(config_file_name, mode="rb") as config:
        try:
            config_dict = load(config)
        except TOMLDecodeError as error:
            raise InvalidConfigurationError(error)

    return config_dict


class InvalidConfigurationError(Exception):
    """The configuration file is invalid TOML"""
