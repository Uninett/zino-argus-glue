#!/usr/bin/env python3
import requests
from pyargus.client import Client
from pyargus.models import Incident
import signal
import ritz
import traceback
import logging
import argparse
import yaml
import sys
from datetime import datetime


_logger = logging.getLogger('zinoargus')

CONFIGFILE = 'config.cfg'
FORMATTER = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

_config = dict()
_args = None
_zino: ritz.ritz = None
_notifier: ritz.notifier = None
_argus: Client = None
_metadata = dict()


def setup_logging():
    '''Configure logging instance'''

    stdout = logging.StreamHandler()
    stdout.setFormatter(FORMATTER)
    _logger.addHandler(stdout)

    verbosity = _args.verbose if _args.verbose else 0
    if not verbosity:
        _logger.setLevel(logging.WARNING)
        stdout.setLevel(logging.WARNING)
        _logger.critical('Enable critical logging')

    elif int(verbosity) == 1:
        _logger.setLevel(logging.INFO)
        stdout.setLevel(logging.INFO)
        _logger.info('Enable informational logging')
    elif int(verbosity) > 1:
        _logger.setLevel(logging.DEBUG)
        stdout.setLevel(logging.DEBUG)
        _logger.debug('Enable debug logging')
        if int(verbosity) > 2:
            # Also enable argus debugging
            # Not Implemented
            pass


def parse_arguments():
    global _args
    arguments = argparse.ArgumentParser()
    arguments.add_argument('-v', '--verbose', action='count')
    _args = arguments.parse_args()


def main():
    global _zino
    global _notifier
    global _argus
    global _config

    parse_arguments()

    # Read configuration
    try:
        with open(CONFIGFILE, 'r') as _f:
            _config = yaml.safe_load(_f)

    except OSError:
        _logger.error('No configuration file found: %s', CONFIGFILE)
        sys.exit(1)

    # Initiate Logging
    setup_logging()

    # Catch SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    _argus = Client(api_root_url=_config.get('api', {}).get('url'),
                    token=_config.get('api', {}).get('token'))

    '''Initiate connectionloop to zino'''
    try:
        _zino = ritz.ritz(server=_config.get('zino', {}).get('server'),
                          port=_config.get('zino', {}).get('port'),
                          username=_config.get('zino', {}).get('user'),
                          password=_config.get('zino', {}).get('secret'))
        _zino.connect()
        _notifier = _zino.init_notifier()

        start()

        # We went out of the loop, reconnect
    except ritz.AuthenticationError:
        _logger.critical('Unable to authenticate against zino, retrying in 30sec')
    except ritz.NotConnectedError:
        _logger.critical('Lost connection with zino, retrying in 30sec')
    except KeyboardInterrupt:
        _logger.critical('CTRL+C detected, exiting application')
    except SystemExit:
        _logger.critical('Recieved sigterm, exiting')
    except Exception:  # pylint: disable=broad-except
        # Break on an unhandled exception
        _logger.critical('Traceback from Main loop:\n%s', traceback.format_exc())
    finally:
        try:
            _zino.close()
        except Exception:
            pass

        _zino = None
        _notifier = None


def collect_metadata():
    global _metadata
    global _config

    r = requests.get(
        url=_config.get('metadata', {}).get('ports_url'))

    r2 = r.json()
    _logger.info('Collected metadata for %s routers', len(r2['data']))
    _logger.info(r2['data'].keys())
    _metadata = r2['data']


def is_down_log(log):
    '''Returns true if any of the log entries '''
    return any(string in log for string in ("linkDown", "lowerLayerDown", "up to down"))


def is_case_interesting(case: ritz.Case):

    if case.type in [ritz.caseType.BFD]:
        _logger.info('Zino case %s of type %s is ignored',
                     case.id,
                     case.type)
        return False

    if case.type in [ritz.caseType.PORTSTATE]:
        logs = (_l["header"] for _l in case.log)
        if not any(is_down_log(_l) for _l in logs):
            return False

    return True


def start():
    ''' This is the Main thread of zino. It will be executed by loop() on a successfull connection,
    And thorn down on a API error from zino or argus'''
    _logger.info('wee are starting')
    # Collect circuit metadata
    collect_metadata()

    # Get all current incidents from Argus
    argus_incidents = dict()
    incident: Incident
    for incident in _argus.get_my_incidents(open=True):
        if not incident.source_incident_id:
            _logger.error('Ignoring incidents no source_incident_id set pk:%s, "%s"',
                          incident.pk, incident.description)
            continue
        if not incident.source_incident_id.isnumeric():
            _logger.error('Ignore incidents %s source_incident_id is not a numeric value (%s)',
                          incident.pk,
                          repr(incident.source_incident_id))
            continue
        _logger.info('Adding argus incidents %s, zino: %s, %s',
                     incident.pk,
                     incident.source_incident_id,
                     repr(incident.description))

        argus_incidents[int(incident.source_incident_id)] = incident

    # Collecting all cases from Zino
    zino_cases = dict()
    case: ritz.Case
    for case in _zino.cases_iter():
        if not is_case_interesting(case):
            continue

        _logger.info('Zino case %s of type %s added',
                     case.id,
                     case.type)
        zino_cases[case.id] = case
    # All cases collected

    # Find cases to delete from argus (case closed in zino)
    for incidentid in set(argus_incidents.keys()) - set(zino_cases.keys()):
        _logger.info('Zino case %s is not cached from zino, and ready to be closed in argus')
        close_argus_incident(argus_incidents[incidentid])

    # Find cases to create in argus
    for caseid in set(zino_cases.keys()) - set(argus_incidents.keys()):
        _logger.info('Zino case %s is not in argus, creating', caseid)
        create_argus_incident(zino_cases[caseid])

    while True:
        update = _notifier.poll(timeout=1)
        if not update:
            # No notification recieved
            continue
        print('Update on case id:"{}" type:"{}" info:"{}"'.format(update.id, update.type, update.info))
        if update.type == "state":
            old_state, new_state = update.info.split(" ", 1)
            if new_state == "closed":
                # Closing case
                _logger.debug('Zino case %s is closed and is being removed from argus', update.id)
                if update.id in argus_incidents:
                    close_argus_incident(argus_incidents[update.id])
                    del argus_incidents[update.id]
                else:
                    _logger.error('Can''t close zino case %s because it''s not found in argus cache', update.id)

                if update.id in zino_cases:
                    del zino_cases[update.id]

            elif old_state == "embryonic" and new_state == "open":
                # Newly created case
                case = _zino.case(update.id)
                if not is_case_interesting(case):
                    continue
                _logger.debug('Creating zino case %s as incident in argus', update.id)
                zino_cases[update.id] = case
                argus_incidents[update.id] = create_argus_incident(case)
            else:
                # All other state changes
                # zino_cases[update.id] = _zino.case(update.id)
                pass
        if update.type == "log":
            _logger.debug("Log message recieved for %s checking if case is in argus", update.id)
            case = _zino.case(update.id)
            if update.id not in argus_incidents:
                # Create ticket if we care about it
                if not is_case_interesting(case):
                    continue
                zino_cases[update.id] = case
                argus_incidents[update.id] = create_argus_incident(case)
            # TODO: Check if content of log should be added as a log entry in argus




def describe_zino_case(zino_case: ritz.Case):
    # TODO: Get correct intial description on interface failures
    if zino_case.type == ritz.caseType.REACHABILITY:
        pass
    elif zino_case.type == ritz.caseType.BGP:
        pass
    elif zino_case.type == ritz.caseType.BFD:
        pass
    elif zino_case.type == ritz.caseType.PORTSTATE:
        return "{} port {} is MEH ({})".format(
            zino_case.router,
            zino_case.port,
            zino_case.get("descr", ""),
        )
    elif zino_case.type == ritz.caseType.ALARM:
        pass
    return None


def generate_tags(zino_case):
    yield "host", zino_case.router
    if zino_case.type == ritz.caseType.PORTSTATE:
        yield "interface", zino_case.port
        descr = zino_case.get("descr")
        if descr:
            yield "description", descr
            # GET UN


def close_argus_incident(argus_incident):
    # TODO: Add timestamp on resolve_incident
    # TODO: Post a description of why this incident is closed
    _logger.info('Deleting argus incident %s',
                 argus_incident.pk)

    _argus.resolve_incident(argus_incident)


def create_argus_incident(zino_case: ritz.Case):
    description = describe_zino_case(zino_case)
    if not description:
        _logger.info('Ignoring zino case %s', zino_case.id)
        return None

    _logger.info('Creating argus incident for zino case %s', zino_case.id)
    print(description)

    incident = Incident(start_time=zino_case.opened,
                        end_time=datetime.max,
                        source_incident_id=zino_case.id,
                        description=description,
                        tags=dict(generate_tags(zino_case)),
                        )
    return _argus.post_incident(incident)


def signal_handler(aignum, frame):
    raise(SystemExit)


if __name__ == '__main__':
    main()
