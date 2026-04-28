"""Synchronous SNMP query to check if a Zino daemon is alive."""

import asyncio

from pysnmp.hlapi.asyncio import (
    CommunityData,
    ContextData,
    ObjectIdentity,
    ObjectType,
    SnmpEngine,
    UdpTransportTarget,
    getCmd,
)

# ZINO-MIB::zinoUpTime.0
ZINO_UPTIME_OID = "1.3.6.1.4.1.2428.130.1.1.1.0"


class ZpingError(Exception):
    """Raised when a Zino uptime query fails."""


def get_zino_uptime(
    host: str = "127.0.0.1",
    port: int = 8000,
    community: str = "public",
    timeout: int = 5,
) -> int:
    """Query a Zino SNMP agent for its uptime.

    :param host: Hostname or IP address of the Zino agent
    :param port: UDP port the Zino SNMP agent listens on
    :param community: SNMP community string
    :param timeout: Timeout in seconds for the SNMP request
    :return: Uptime in seconds
    :raises ZpingError: When the agent is unreachable or returns an error
    """
    return asyncio.run(_get_zino_uptime(host, port, community, timeout))


async def _get_zino_uptime(host: str, port: int, community: str, timeout: int) -> int:
    snmp_engine = SnmpEngine()

    try:
        error_indication, error_status, error_index, var_binds = await getCmd(
            snmp_engine,
            CommunityData(community),
            UdpTransportTarget((host, port), timeout=timeout, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity(ZINO_UPTIME_OID)),
        )
    except Exception as exc:
        snmp_engine.closeDispatcher()
        raise ZpingError(f"SNMP request failed: {exc}") from exc

    snmp_engine.closeDispatcher()

    if error_indication:
        raise ZpingError(str(error_indication))
    if error_status:
        raise ZpingError(
            f"SNMP error: {error_status.prettyPrint()} at "
            f"{var_binds[int(error_index) - 1][0] if error_index else '?'}"
        )
    if not var_binds:
        raise ZpingError("Empty response from agent")

    _, value = var_binds[0]
    return int(value)
