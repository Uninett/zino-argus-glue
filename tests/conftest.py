#
# Fixtures
#
import socket
import subprocess
import time

import pytest


def pytest_configure(config):
    # This forces an argus version that works (as of this writing, the latest
    # docker images are broken)
    config.option.argus_version = "1.30.0"


@pytest.fixture
def zino(zino_configuration_file):
    cwd = zino_configuration_file.parent
    process = subprocess.Popen(
        ["zino", "--trap-port", "0", "--config-file", zino_configuration_file], cwd=cwd
    )
    wait_for_zino_api()
    yield process
    process.terminate()


def wait_for_zino_api():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    retries = 5
    for _ in range(retries):
        try:
            s.connect(("localhost", 8001))
            s.close()
            return
        except socket.error:
            time.sleep(1)
    pytest.fail("Could not connect to port 8001 after multiple retries")


@pytest.fixture
def zino_configuration_file(
    tmp_path, zino_polldevs_configuration_file, zino_secrets_file
):
    name = tmp_path / "zino.toml"
    with open(name, "w") as conf:
        conf.write(
            f"""
            [archiving]
            old_events_dir = "old-events"

            [authentication]
            file = "{zino_secrets_file}"

            [persistence]
            file = "zino-state.json"
            period = 5

            [polling]
            file = "{zino_polldevs_configuration_file}"
            period = 1

            [snmp]
            backend = "netsnmp"
            """
        )
    yield name


@pytest.fixture
def zino_polldevs_configuration_file(tmp_path):
    name = tmp_path / "polldevs.cf"
    with open(name, "w") as conf:
        conf.write(
            """
            default interval: 5
            default community: public
            default domain: example.org

            name: example-gw
            address: 127.0.0.1
            """
        )
    yield name


@pytest.fixture
def zino_secrets_file(zino_test_user, tmp_path):
    name = tmp_path / "secrets"
    username, password = zino_test_user
    with open(name, "w") as conf:
        conf.write(f"{username} {password}\n")
    yield name


@pytest.fixture
def zino_test_user() -> tuple[str, str]:
    return "testuser", "testpassword"
