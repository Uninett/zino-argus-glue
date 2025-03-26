#
# Copyright 2025 Sikt
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from os import PathLike
from typing import Union

from pydantic import ValidationError

from .models import Configuration

try:
    from tomllib import TOMLDecodeError, load
except ImportError:
    from tomli import TOMLDecodeError, load


def read_configuration(config_file_name: Union[str, PathLike[str]]) -> Configuration:
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

    try:
        return Configuration.model_validate(obj=config_dict, strict=True)
    except ValidationError as error:
        raise InvalidConfigurationError(error)


class InvalidConfigurationError(Exception):
    """The configuration file is invalid"""
