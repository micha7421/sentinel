import ipaddress
import pytest
from sentinel import ipintel


@pytest.fixture
def lists(tmp_path, monkeypatch):
    d = tmp_path / "lists"
    d.mkdir()
    (d / "tor.txt").write_text("185.220.101.5\n")
    (d / "vpn4.txt").write_text("2.26.8.0/22\n")
    (d / "hosting4.txt").write_text("8.8.8.0/24\n")
    (d / "vpn6.txt").write_text("")
    (d / "hosting6.txt").write_text("")
    monkeypatch.setattr(ipintel, "_lists_dir", lambda: d)
    ipintel._ranges.clear()
    ipintel._cache.clear()
    return d


def test_in_list(lists):
    assert ipintel.in_list(ipaddress.ip_address("185.220.101.5"), "tor")
    assert ipintel.in_list(ipaddress.ip_address("2.26.9.1"), "vpn4")
    assert not ipintel.in_list(ipaddress.ip_address("9.9.9.9"), "vpn4")


@pytest.mark.parametrize("ip,kind", [
    ("185.220.101.5", "tor"),
    ("2.26.9.1", "vpn"),
    ("8.8.8.8", "hosting"),
    ("192.168.1.1", "local"),
    ("203.0.113.5", "test"),
    ("9.9.9.9", "unknown"),
])
def test_lookup_kind(lists, ip, kind):
    assert ipintel.lookup(ip, online=False)["kind"] == kind


def test_merged_ranges_lookup(tmp_path, monkeypatch):
    d = tmp_path / "l"
    d.mkdir()
    # overlapping + adjacent ranges must still resolve correctly
    (d / "vpn4.txt").write_text("10.0.0.0/24\n10.0.1.0/24\n10.0.0.128/25\n")
    monkeypatch.setattr(ipintel, "_lists_dir", lambda: d)
    ipintel._ranges.clear()
    assert ipintel.in_list(ipaddress.ip_address("10.0.1.255"), "vpn4")
    assert not ipintel.in_list(ipaddress.ip_address("10.0.2.0"), "vpn4")


def test_abuse_emails():
    rdap = {"entities": [{"roles": ["registrant"], "entities": [
        {"roles": ["abuse"], "vcardArray": ["vcard", [
            ["version", {}, "text", "4.0"],
            ["email", {}, "text", "abuse@example.net"]]]}]}]}
    assert ipintel._abuse_emails(rdap) == ["abuse@example.net"]
