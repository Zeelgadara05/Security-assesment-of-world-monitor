"""Target validation: only domains, IPv4 addresses, and CIDR blocks are accepted."""

from database.schemas import ScanRequest


def test_valid_domain():
    assert ScanRequest(target="example.com").target == "example.com"


def test_valid_domain_with_protocol_is_normalized():
    assert ScanRequest(target="https://sub.example.com").target == "sub.example.com"


def test_valid_ipv4():
    assert ScanRequest(target="104.244.42.1").target == "104.244.42.1"


def test_valid_cidr():
    assert ScanRequest(target="192.168.1.0/24").target == "192.168.1.0/24"


def test_valid_https_with_port_is_stripped():
    assert ScanRequest(target="https://example.com:8080").target == "example.com"


INVALID_TARGETS = [
    "not a domain",
    "javascript:alert(1)",
    "http://",
    "999.999.999.999",
]


def test_invalid_targets_rejected_by_api(client):
    for bad in INVALID_TARGETS:
        resp = client.post("/scans/trigger", json={"target": bad})
        assert resp.status_code == 422, f"{bad!r} should be rejected, got {resp.status_code}"


def test_empty_target_rejected_by_api(client):
    resp = client.post("/scans/trigger", json={"target": ""})
    assert resp.status_code == 422