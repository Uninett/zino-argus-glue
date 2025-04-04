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

"""Zino configuration models"""

from typing import Literal, Optional, Union

from pydantic import AnyHttpUrl, BaseModel, ConfigDict, IPvAnyAddress

Host = Union[IPvAnyAddress, str]


class ArgusConfiguration(BaseModel):
    """Argus API connection configuration"""

    model_config = ConfigDict(extra="forbid")

    url: AnyHttpUrl
    token: str


class ZinoConfiguration(BaseModel):
    """Zino API connection configuration"""

    model_config = ConfigDict(extra="forbid")

    server: Host
    port: int = 8001
    user: str
    secret: str


class MetadataConfiguration(BaseModel):
    """Class for modeling port metadata retrieval configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    ports_url: Optional[AnyHttpUrl] = None


class AcknowledgeSyncConfiguration(BaseModel):
    """Class for modeling acknowledgment synchronization configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    setstate: Literal["none", "working", "waiting"] = "none"


class SyncConfiguration(BaseModel):
    """Class for modeling synchronization behavior configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    acknowledge: Optional[AcknowledgeSyncConfiguration] = AcknowledgeSyncConfiguration()


class Configuration(BaseModel):
    """Class for modeling the Zino-Argus glue service configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    argus: ArgusConfiguration
    zino: ZinoConfiguration
    sync: Optional[SyncConfiguration] = SyncConfiguration()
    metadata: Optional[MetadataConfiguration] = MetadataConfiguration()
