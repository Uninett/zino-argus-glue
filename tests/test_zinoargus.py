import pytest

from zinoargus import is_down_log


@pytest.mark.parametrize("log_message", ["linkDown", "lowerLayerDown", "up to down"])
def test_when_log_message_indicates_down_events_it_should_return_true(log_message):
    assert is_down_log(log_message)
