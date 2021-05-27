#!/usr/bin/env python3
import requests
import configparser
from pyargus.client import Client
from pyargus.models import Incident
import signal
import ritz
import traceback
import logging
import argparse
# import time


_logger = logging.getLogger('zinoargus')

CONFIGFILE = 'config.cfg'
FORMATTER = logging.Formatter(
    '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

_config = configparser.ConfigParser(allow_no_value=True)
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

    parse_arguments()

    # Read configuration
    _config.read(CONFIGFILE)

    # Initiate Logging
    setup_logging()

    # Catch SIGTERM
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    _argus = Client(api_root_url=_config.get('argus', 'server'),
                    token=_config.get('argus', 'token'))

    '''Initiate connectionloop to zino'''
    try:
        _zino = ritz.ritz(server=_config.get('zino', 'server'),
                          port=_config.get('zino', 'port'),
                          username=_config.get('zino', 'user'),
                          password=_config.get('zino', 'secret'))
        _zino.connect()
        _notifier = ritz.notifier(_zino)
        _notifier.connect()

        start()

        _zino.close()
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

        _zino = None
        _notifier = None


def collect_metadata():
    global _metadata

    r = requests.get(
        url=_config.get('metadata', 'ports'))

    r2 = r.json()
    _logger.info('Collected metadata for %s routers', len(r2['data']))
    _logger.info(r2['data'].keys())
    _metadata = r2['data']


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
        if case.type in [ritz.caseType.BFD]:
            _logger.info('Zino case %s of type %s is ignored',
                         case.id,
                         case.type)
            continue

        if case.type not in [ritz.caseType.REACHABILITY]:
            _logger.info('Zino case %s of type %s ignored to not overflow collection',
                         case.id,
                         case.type)
            continue

        _logger.info('Zino case %s of type %s added',
                     case.id,
                     case.type)
        zino_cases[case.id] = case

    # All cases collected

    # Find cases to delete from argus (case closed in zino)
    for incidentid in set(argus_incidents.keys()) - set(zino_cases.keys()):
        _logger.info('Zino tocket %s is not cached from zino, and ready to be closed in argus')
        close_argus_incident(argus_incidents[incidentid])

    # Find cases to create in argus
    for caseid in set(zino_cases.keys()) - set(argus_incidents.keys()):
        _logger.info('Zino ticket %s is not in argus, creating', caseid)
        create_argus_incident(zino_cases[caseid])


def close_argus_incident(argus_ticket):
    _logger.info('Deleting argus incident %s, buuuut its not implemented yet ... :/',
                 argus_ticket.pk)


def create_argus_incident(zino_ticket):
    _logger.info('Creating incident %s in argus, buuuut its not implemented yet ... :/',
                 zino_ticket.id)


def signal_handler(aignum, frame):
    raise(SystemExit)


if __name__ == '__main__':
    main()
