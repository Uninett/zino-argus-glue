#!/usr/bin/env python3
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
import argparse
import logging
import signal
import sys
from datetime import datetime

import requests
import zinolib as ritz
from pyargus.client import Client
from pyargus.models import Incident
from simple_rest_client.exceptions import ClientConnectionError

from zinoargus.config import (
    Configuration,
    InvalidConfigurationError,
    read_configuration,
)

# A map of Zino case numbers to Zino case objects
CaseMap = dict[int, ritz.Case]
# A map of Zino case numbers to Argus incident objects
IncidentMap = dict[int, Incident]

_logger = logging.getLogger("zinoargus")

FORMATTER = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

_config: Configuration = None
_zino: ritz.ritz = None
_notifier: ritz.notifier = None
_argus: Client = None
_metadata = dict()


def main():
    global _zino
    global _notifier
    global _argus
    global _config

    args = parse_arguments()

    # Read configuration
    try:
        _config = read_configuration(args.config_file)
    except OSError:
        _logger.error("No configuration file found: %s", args.config_file)
        sys.exit(1)
    except InvalidConfigurationError as error:
        _logger.error("Invalid configuration in file %s: %s", args.config_file, error)
        sys.exit(1)

    # Initiate Logging
    setup_logging(verbosity=args.verbose or 0)

    # Catch SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    _argus = Client(
        api_root_url=str(_config.argus.url),
        token=_config.argus.token,
    )

    """Initiate connectionloop to zino"""
    try:
        _zino = ritz.ritz(
            server=str(_config.zino.server),
            port=_config.zino.port,
            username=_config.zino.user,
            password=_config.zino.secret,
        )
        _zino.connect()
        _notifier = _zino.init_notifier()

        start()

        # We went out of the loop, reconnect
    except ritz.AuthenticationError:
        _logger.critical("Unable to authenticate against zino, retrying in 30sec")
    except ritz.NotConnectedError:
        _logger.critical("Lost connection with zino, retrying in 30sec")
    except ConnectionRefusedError:
        _logger.critical(
            "Connection refused by Zino (%s:%s)", _config.zino.server, _config.zino.port
        )
    except ClientConnectionError:
        _logger.critical("Connection refused by Argus (%s)", _config.argus.url)
    except KeyboardInterrupt:
        _logger.critical("CTRL+C detected, exiting application")
    except SystemExit:
        _logger.critical("Received sigterm, exiting")
    except Exception:  # pylint: disable=broad-except
        # Break on an unhandled exception
        _logger.critical("Unhandled exception from main event loop", exc_info=True)
    finally:
        try:
            _zino.close()
        except Exception:  # noqa
            pass

        _zino = None
        _notifier = None


def start():
    """This is the main "event loop" of the Zino-Argus glue service, called when there
    are successful connections to the Zino and Argus API, and torn down when the
    connections or API's fail.
    """
    _logger.info("starting")
    # Collect circuit metadata
    collect_metadata()

    argus_incidents, zino_cases = synchronize_all_cases()
    synchronize_continuously(argus_incidents, zino_cases)


def synchronize_all_cases() -> tuple[IncidentMap, CaseMap]:
    """Fully synchronize cases/incidents between Zino and Argus, returning maps of all
    known Argus incidents and all Zino cases.
    """
    argus_incidents = get_all_my_argus_incidents()
    zino_cases = get_all_interesting_zino_cases()

    close_argus_incidents_missing_from_zino(argus_incidents, zino_cases)
    create_argus_incidents_from_new_zino_cases(argus_incidents, zino_cases)

    return argus_incidents, zino_cases


def get_all_my_argus_incidents() -> IncidentMap:
    """Get a map of all Argus incidents that belong to the source system represented by
    this glue service instance.
    """
    argus_incidents: IncidentMap = {}
    for incident in _argus.get_my_incidents(open=True):
        if not incident.source_incident_id:
            _logger.error(
                "Ignoring incident %s with no 'source_incident_id' set (%r)",
                incident.pk,
                incident.description,
            )
            continue
        if not incident.source_incident_id.isnumeric():
            _logger.error(
                "Ignoring incident %s (%r), source_incident_id is not a numeric value (%r)",
                incident.pk,
                incident.description,
                incident.source_incident_id,
            )
            continue
        _logger.debug(
            "Argus incident %s (zino case #%s) added to to internal data structures (%r)",
            incident.pk,
            incident.source_incident_id,
            incident.description,
        )

        argus_incidents[int(incident.source_incident_id)] = incident
    return argus_incidents


def get_all_interesting_zino_cases() -> CaseMap:
    """Returns a map of all Zino cases that are deeming interesting enough to
    synchronize to Argus.
    """
    zino_cases: CaseMap = {}
    case: ritz.Case
    for case in _zino.cases_iter():
        if not is_case_interesting(case):
            continue

        _logger.debug(
            "Zino case #%s of type %s (%s) added to internal data structure",
            case.id,
            case.type,
            case.get("router"),
        )
        zino_cases[case.id] = case

    return zino_cases


def create_argus_incidents_from_new_zino_cases(argus_incidents, zino_cases):
    for case_id in set(zino_cases) - set(argus_incidents):
        _logger.info("Zino case %s is not in Argus, creating", case_id)
        create_argus_incident(zino_cases[case_id])


def close_argus_incidents_missing_from_zino(argus_incidents, zino_cases):
    for case_id in set(argus_incidents) - set(zino_cases):
        _logger.info(
            "Zino case %s is not cached from zino, and ready to be closed in argus",
            case_id,
        )
        close_argus_incident(
            argus_incidents[case_id],
            description="This case did not exist in zino when glue service was started",
        )


def synchronize_continuously(argus_incidents: IncidentMap, zino_cases: CaseMap):
    """Continuously "poll" the Zino notification channel and update Argus accordingly"""
    while True:
        update = _notifier.poll(timeout=1)
        if not update:
            # No notification received
            continue
        print(
            'Update on case id:"{}" type:"{}" info:"{}"'.format(
                update.id, update.type, update.info
            )
        )
        if update.type == "state":
            old_state, new_state = update.info.split(" ", 1)
            if new_state == "closed":
                # Closing case
                _logger.debug(
                    "Zino case %s is closed and is being removed from argus", update.id
                )
                if update.id in argus_incidents:
                    close_argus_incident(
                        argus_incidents[update.id],
                        description="Zino case closed by user",
                    )
                    del argus_incidents[update.id]
                else:
                    _logger.info(
                        "Can't close zino case %s because it's not found in argus",
                        update.id,
                    )

                if update.id in zino_cases:
                    del zino_cases[update.id]

            elif old_state == "embryonic" and new_state == "open":
                # Newly created case
                case = _zino.case(update.id)
                if update.id not in argus_incidents:
                    if not is_case_interesting(case):
                        continue
                    _logger.debug(
                        "Creating zino case %s as incident in argus", update.id
                    )
                    zino_cases[update.id] = case
                    argus_incidents[update.id] = create_argus_incident(case)
                else:
                    _logger.debug("Zino case {} is already added to argus")
            else:
                # All other state changes
                # zino_cases[update.id] = _zino.case(update.id)
                pass
        if update.type == "log":
            _logger.debug(
                "Log message received for %s checking if case is in argus", update.id
            )
            case = _zino.case(update.id)
            if update.id not in argus_incidents:
                # Create ticket if we care about it
                if not is_case_interesting(case):
                    continue
                zino_cases[update.id] = case
                argus_incidents[update.id] = create_argus_incident(case)
        # TODO: Add content of zino history as incident events in argus
        # TODO: Pri1 next time :)


def collect_metadata():
    global _metadata
    global _config

    metadata_url = _config.metadata.ports_url
    if not metadata_url:
        return

    r = requests.get(url=metadata_url)

    r2 = r.json()
    _logger.info("Collected metadata for %s routers", len(r2["data"]))
    _logger.info(r2["data"].keys())
    _metadata = r2["data"]


def is_down_log(log):
    """Returns true if any of the log entries"""
    return any(string in log for string in ("linkDown", "lowerLayerDown", "up to down"))


def is_production_interface(case: ritz.Case):
    # All interfaces in production should follow the correct description syntax
    if "descr" in case.keys():
        return "," in case.descr
    return False


def is_case_interesting(case: ritz.Case):
    # TODO: Add metadata from telemator and check importance against circuit type

    if case.type in [ritz.caseType.BFD]:
        _logger.info("Zino case %s of type %s is ignored", case.id, case.type)
        return False

    if case.type in [ritz.caseType.PORTSTATE]:
        logs = (_l["header"] for _l in case.log)
        if not any(is_down_log(_l) for _l in logs):
            return False
        if not is_production_interface(case):
            return False

    return True


def describe_zino_case(zino_case: ritz.Case):
    if zino_case.type == ritz.caseType.REACHABILITY:
        return f"{zino_case.router} is not reachable"
    elif zino_case.type == ritz.caseType.BGP:
        # TODO: Lookup remote_addr name in reverse-DNS
        return f"{zino_case.router} BGP Neighbor AS{zino_case.remote_as}/{zino_case.remote_addr} is DOWN"
    elif zino_case.type == ritz.caseType.BFD:
        # BFD should be ignored
        pass
    elif zino_case.type == ritz.caseType.PORTSTATE:
        return f"{zino_case.router} port {zino_case.port} changed state to DOWN ({zino_case.get('descr', '')})"
    elif zino_case.type == ritz.caseType.ALARM:
        return f"{zino_case.router} Active alarms reported"
    return None


def generate_tags(zino_case):
    yield "host", zino_case.router
    if zino_case.type == ritz.caseType.PORTSTATE:
        yield "interface", zino_case.port
        descr = zino_case.get("descr")
        if descr:
            yield "description", descr
            # GET UN


def close_argus_incident(argus_incident, description=None):
    # TODO: Add timestamp on resolve_incident
    _logger.info("Deleting argus incident %s", argus_incident.pk)

    _argus.resolve_incident(argus_incident, description=description)


def create_argus_incident(zino_case: ritz.Case):
    description = describe_zino_case(zino_case)
    if not description:
        _logger.info("Ignoring zino case %s", zino_case.id)
        return None

    _logger.info("Creating argus incident for zino case %s", zino_case.id)

    incident = Incident(
        start_time=zino_case.opened,
        end_time=datetime.max,
        source_incident_id=zino_case.id,
        description=description,
        tags=dict(generate_tags(zino_case)),
    )
    return _argus.post_incident(incident)


def setup_logging(verbosity: int = 0):
    """Configure logging instance"""

    stdout = logging.StreamHandler()
    stdout.setFormatter(FORMATTER)
    root = logging.getLogger()
    root.addHandler(stdout)
    # Disabling redundant exception logging from simple_rest_client library
    logging.getLogger("simple_rest_client.decorators").setLevel(logging.CRITICAL)

    if not verbosity:
        root.setLevel(logging.WARNING)
        _logger.critical("Enable critical logging")

    elif int(verbosity) == 1:
        root.setLevel(logging.INFO)
        _logger.info("Enable informational logging")
    elif int(verbosity) > 1:
        root.setLevel(logging.DEBUG)
        _logger.debug("Enable debug logging")
        if int(verbosity) > 2:
            # Also enable argus debugging
            # Not Implemented
            pass


def parse_arguments() -> argparse.Namespace:
    arguments = argparse.ArgumentParser()
    arguments.add_argument("-v", "--verbose", action="count")
    arguments.add_argument("-c", "--config-file", default="zinoargus.toml")
    return arguments.parse_args()


def signal_handler(_signum, _frame):
    raise SystemExit()


if __name__ == "__main__":
    main()
