"""Tests Zino integration with the test environment, not for the glue service itself"""


def test_zino_should_run(zino):
    """This tests that Zino can be run in this test environment"""
    assert zino.poll() is None
