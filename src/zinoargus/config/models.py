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

from typing import List, Literal, Optional, Union

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    PositiveFloat,
)

Host = Union[IPvAnyAddress, str]


class ArgusConfiguration(BaseModel):
    """Argus API connection configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    url: AnyHttpUrl
    token: str
    timeout: PositiveFloat = 2.0


class ZinoConfiguration(BaseModel):
    """Zino API connection configuration"""

    model_config = ConfigDict(extra="forbid")

    server: Host
    port: int = 8001
    user: str
    secret: str
    default_domain: Optional[str] = None


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


class TicketSyncConfiguration(BaseModel):
    """Class for modeling ticket synchronization configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    enable: bool = False


class SeverityBand(BaseModel):
    """A single Zino-priority-to-Argus-level mapping band.

    A case is assigned this band's Argus ``level`` when its Zino ``priority``
    is greater than or equal to ``min_priority``.
    """

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    min_priority: int = Field(ge=0)
    # Argus levels run 1 (Critical) to 5 (Information); lower is more severe.
    level: int = Field(ge=1, le=5)


class SeverityConfiguration(BaseModel):
    """Class for modeling Argus incident severity mapping configuration.

    Maps a Zino case's ``priority`` (higher means more important) to an Argus
    incident ``level`` (1=Critical .. 5=Information; lower means more severe).
    """

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    # Argus level used when a case's priority is below every configured band.
    default: int = Field(default=3, ge=1, le=5)
    thresholds: List[SeverityBand] = Field(default_factory=list)


class SyncConfiguration(BaseModel):
    """Class for modeling synchronization behavior configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    acknowledge: Optional[AcknowledgeSyncConfiguration] = AcknowledgeSyncConfiguration()
    ticket: Optional[TicketSyncConfiguration] = TicketSyncConfiguration()
    # Severity mapping is always active: an absent [sync.severity] block yields
    # these defaults, so every Argus incident gets an explicit level (3/Moderate
    # by default) rather than relying on Argus's own server-side default.
    severity: SeverityConfiguration = SeverityConfiguration()


class FailoverConfiguration(BaseModel):
    """Configuration for primary/secondary failover mode"""

    model_config = ConfigDict(extra="forbid")

    primary_server: Host
    primary_snmp_port: int = 8000
    snmp_community: str = "public"
    ping_timeout: int = 5
    threshold: int = 10


class Configuration(BaseModel):
    """Class for modeling the Zino-Argus glue service configuration"""

    # throw ValidationError on extra keys
    model_config = ConfigDict(extra="forbid")

    argus: ArgusConfiguration
    zino: ZinoConfiguration
    sync: Optional[SyncConfiguration] = SyncConfiguration()
    metadata: Optional[MetadataConfiguration] = MetadataConfiguration()
    failover: Optional[FailoverConfiguration] = None
