from types import SimpleNamespace

import pytest

import zinoargus
from zinoargus import generate_tags


class FakeCase:
    """Minimal stand-in for a ritz.Case exposing the bits generate_tags uses."""

    def __init__(self, type, router="rtr1", priority=100, **attrs):
        self.type = type
        self.router = router
        self.priority = priority
        self._attrs = attrs

    def __getattr__(self, name):
        return self._attrs[name]

    def get(self, key, default=None):
        return self._attrs.get(key, default)


class TestGenerateTags:
    def test_when_any_case_then_it_should_always_tag_event_type_and_priority(
        self, no_domain_config
    ):
        case = FakeCase(zinoargus.ritz.caseType.REACHABILITY, priority=200)
        tags = dict(generate_tags(case))
        assert tags["event_type"] == "reachability"
        assert tags["priority"] == "200"
        assert tags["host"] == "rtr1"

    def test_when_portstate_case_then_it_should_tag_interface_and_description(
        self, no_domain_config
    ):
        case = FakeCase(
            zinoargus.ritz.caseType.PORTSTATE,
            port="GigabitEthernet0/1",
            descr="uplink, to core",
        )
        tags = dict(generate_tags(case))
        assert tags["interface"] == "GigabitEthernet0/1"
        assert tags["description"] == "uplink, to core"

    def test_when_portstate_case_without_descr_then_it_should_omit_description(
        self, no_domain_config
    ):
        case = FakeCase(zinoargus.ritz.caseType.PORTSTATE, port="ge-0/0/0")
        tags = dict(generate_tags(case))
        assert "description" not in tags

    def test_when_bgp_case_then_it_should_tag_remote_as_and_remote_addr(
        self, no_domain_config
    ):
        case = FakeCase(
            zinoargus.ritz.caseType.BGP, remote_as=64512, remote_addr="192.0.2.1"
        )
        tags = dict(generate_tags(case))
        assert tags["remote_as"] == "64512"
        assert tags["remote_addr"] == "192.0.2.1"

    def test_when_bgp_case_without_peer_attrs_then_it_should_omit_them(
        self, no_domain_config
    ):
        case = FakeCase(zinoargus.ritz.caseType.BGP)
        tags = dict(generate_tags(case))
        assert "remote_as" not in tags
        assert "remote_addr" not in tags

    def test_when_default_domain_set_then_it_should_qualify_the_host_tag(
        self, monkeypatch
    ):
        _domain_config(monkeypatch, "example.org")
        case = FakeCase(zinoargus.ritz.caseType.REACHABILITY, router="rtr1")
        tags = dict(generate_tags(case))
        assert tags["host"] == "rtr1.example.org"


class TestQualifyHost:
    def test_when_domain_set_and_name_bare_then_it_should_append_domain(
        self, monkeypatch
    ):
        _domain_config(monkeypatch, "example.org")
        assert zinoargus._qualify_host("rtr1") == "rtr1.example.org"

    def test_when_name_already_qualified_then_it_should_return_unchanged(
        self, monkeypatch
    ):
        _domain_config(monkeypatch, "example.org")
        assert zinoargus._qualify_host("rtr1.other.net") == "rtr1.other.net"

    def test_when_domain_unset_then_it_should_return_unchanged(self, no_domain_config):
        assert zinoargus._qualify_host("rtr1") == "rtr1"

    def test_when_domain_is_empty_string_then_it_should_return_unchanged(
        self, monkeypatch
    ):
        _domain_config(monkeypatch, "")
        assert zinoargus._qualify_host("rtr1") == "rtr1"


@pytest.fixture
def no_domain_config(monkeypatch):
    monkeypatch.setattr(
        zinoargus, "_config", SimpleNamespace(zino=SimpleNamespace(default_domain=None))
    )


def _domain_config(monkeypatch, domain):
    monkeypatch.setattr(
        zinoargus,
        "_config",
        SimpleNamespace(zino=SimpleNamespace(default_domain=domain)),
    )
