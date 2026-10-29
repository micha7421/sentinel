"""Blocking attackers with nftables.

Sentinel uses its own small table ("inet sentinel"), so it never touches
your other firewall rules. Blocks expire on their own after a while.
"""

import ipaddress
import json
import logging
import shutil
import subprocess

log = logging.getLogger("sentinel")

TABLE = "sentinel"
RULES = f"""
table inet {TABLE} {{
    set blocked4 {{ type ipv4_addr; flags timeout; }}
    set blocked6 {{ type ipv6_addr; flags timeout; }}
    chain input {{
        type filter hook input priority -10; policy accept;
        ip saddr @blocked4 drop
        ip6 saddr @blocked6 drop
    }}
}}
"""


def available():
    return shutil.which("nft") is not None


def _nft(*args, input_text=None):
    r = subprocess.run(["nft", *args], input=input_text, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip() or "nft failed")
    return r.stdout


def setup():
    """Create Sentinel's table if it isn't there yet. Returns False on failure."""
    if not available():
        log.warning("nft not found, attackers can't be blocked "
                    "(install net-firewall/nftables).")
        return False
    try:
        _nft("list", "table", "inet", TABLE)
        return True
    except RuntimeError:
        pass
    try:
        _nft("-f", "-", input_text=RULES)
        return True
    except RuntimeError as e:
        log.error("Could not create firewall table: %s", e)
        return False


def _set_for(ip):
    return "blocked4" if ipaddress.ip_address(ip).version == 4 else "blocked6"


def block(ip, hours):
    ip = str(ipaddress.ip_address(ip))  # refuses anything that isn't an IP
    _nft("add", "element", "inet", TABLE, _set_for(ip),
         f"{{ {ip} timeout {int(hours * 3600)}s }}")


def unblock(ip):
    ip = str(ipaddress.ip_address(ip))
    _nft("delete", "element", "inet", TABLE, _set_for(ip), f"{{ {ip} }}")


def blocked():
    """[{'ip': ..., 'expires_in': seconds}, ...]"""
    result = []
    for name in ("blocked4", "blocked6"):
        try:
            data = json.loads(_nft("-j", "list", "set", "inet", TABLE, name))
        except (RuntimeError, json.JSONDecodeError):
            continue
        for item in data.get("nftables", []):
            for elem in item.get("set", {}).get("elem", []):
                if isinstance(elem, dict) and "elem" in elem:
                    e = elem["elem"]
                    result.append({"ip": e["val"], "expires_in": e.get("expires", 0)})
                else:
                    result.append({"ip": elem, "expires_in": 0})
    return result


def remove():
    try:
        _nft("delete", "table", "inet", TABLE)
    except RuntimeError:
        pass
