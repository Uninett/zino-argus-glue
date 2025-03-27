import subprocess
import time

import pytest

from zinoargus import is_down_log


@pytest.mark.parametrize("log_message", ["linkDown", "lowerLayerDown", "up to down"])
def test_when_log_message_indicates_down_events_it_should_return_true(log_message):
    assert is_down_log(log_message)


@pytest.mark.slow
def test_zinoargus_should_not_crash_at_startup(zinoargus_external_run):
    delay = 3
    assert zinoargus_external_run.poll() is None, "zinoargus failed immediately"
    time.sleep(delay)
    assert zinoargus_external_run.poll() is None, (
        f"zinoargus failed within {delay} seconds"
    )


#
# Fixtures
#


@pytest.fixture
def zinoargus_external_run(zino, zinoargus_configuration_file):
    process = subprocess.Popen(["zinoargus", "-c", zinoargus_configuration_file])
    yield process
    process.terminate()


@pytest.fixture
def zinoargus_configuration_file(
    tmp_path, zino_test_user, argus_api_url, argus_source_system_token
):
    name = tmp_path / "zinoargus.toml"
    zino_user, zino_password = zino_test_user
    with open(name, "w") as conf:
        conf.write(
            f"""
            [argus]
            url = "{argus_api_url}"
            token = "{argus_source_system_token}"

            [zino]
            server = "localhost"
            port = 8001
            user = "{zino_user}"
            secret = "{zino_password}"
            """
        )
    yield name
