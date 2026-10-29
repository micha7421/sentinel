import socket
import struct
import pytest
from sentinel import breakin, config


@pytest.mark.parametrize("line,expected", [
    ("Failed password for root from 185.220.101.5 port 41234 ssh2", ("185.220.101.5", "root")),
    ("Failed password for invalid user admin from 2001:db8::7 port 22 ssh2", ("2001:db8::7", "admin")),
    ("Invalid user oracle from 45.1.2.3 port 5555", ("45.1.2.3", "oracle")),
    ("Accepted publickey for michael from 192.168.1.5 port 50000 ssh2", None),
    ("random unrelated log line", None),
])
def test_parse_ssh_line(line, expected):
    assert breakin.parse_ssh_line(line) == expected


def test_parse_syn_ipv4():
    p = bytearray(24)
    p[0] = 0x45           # IPv4, ihl=5 (20 bytes)
    p[9] = 6              # TCP
    p[12:16] = socket.inet_aton("203.0.113.9")
    struct.pack_into("!H", p, 22, 8080)   # dest port at ihl+2
    assert breakin.parse_syn(bytes(p)) == ("203.0.113.9", 8080)


def test_parse_syn_ipv6():
    p = bytearray(44)
    p[0] = 0x60           # IPv6
    p[8:24] = socket.inet_pton(socket.AF_INET6, "2001:db8::7")
    struct.pack_into("!H", p, 42, 443)
    src, port = breakin.parse_syn(bytes(p))
    assert ipaddr(src) == ipaddr("2001:db8::7") and port == 443


def ipaddr(s):
    import ipaddress
    return ipaddress.ip_address(s)


def test_parse_syn_garbage():
    assert breakin.parse_syn(b"\x00\x01") is None


def test_is_trusted():
    cfg = dict(config.DEFAULTS)
    cfg["trusted_ips"] = ["127.0.0.0/8", "192.168.0.0/16"]
    g = breakin.BreakinGuard(cfg, ignore_own=False)
    assert g.is_trusted("127.0.0.1")
    assert g.is_trusted("192.168.1.50")
    assert not g.is_trusted("8.8.8.8")


def test_read_attacks_status(tmp_path, monkeypatch):
    import json
    import time
    f = tmp_path / "attacks.jsonl"
    monkeypatch.setattr(config, "ATTACKS_FILE", f)
    now = time.time()
    rows = [
        {"type": "attack", "time": now - 10, "ip": "1.1.1.1", "attack": "x",
         "detail": "d", "blocked": True, "block_hours": 24, "info": {}},
        {"type": "attack", "time": now - 10, "ip": "2.2.2.2", "attack": "x",
         "detail": "d", "blocked": True, "block_hours": 0.0001, "info": {}},  # expired
        {"type": "attack", "time": now - 10, "ip": "3.3.3.3", "attack": "x",
         "detail": "d", "blocked": False, "block_hours": 24, "info": {}},
        {"type": "unblock", "ip": "1.1.1.1", "time": now - 5},
    ]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    by_ip = {a["ip"]: a["status"] for a in breakin.read_attacks()}
    assert by_ip["1.1.1.1"] == "unblocked"
    assert by_ip["2.2.2.2"] == "expired"
    assert by_ip["3.3.3.3"] == "not blocked"
