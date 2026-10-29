"""Who is behind an IP address?

1. Offline lists (downloaded once a day): Tor exit nodes, known VPN
   providers, and data centers (rented servers).
2. Online lookups (optional): rough location and internet provider
   (ipinfo.io), and the official owner + abuse e-mail (RDAP, run by the
   internet registries).

The answer is a guess, not proof: VPN lists are never complete.
"""

import bisect
import ipaddress
import json
import logging
import time
import urllib.request

from . import config

log = logging.getLogger("sentinel")

LISTS = {
    "tor": ["https://check.torproject.org/torbulkexitlist",
            "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst"],
    "vpn4": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"],
    "vpn6": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv6.txt"],
    "hosting4": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"],
    "hosting6": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv6.txt"],
}
MAX_AGE = 24 * 3600

# Internet providers whose name gives away that it's a rented server.
HOSTING_WORDS = ("hosting", "cloud", "server", "datacenter", "data center",
                 "vps", "ovh", "hetzner", "digitalocean", "amazon", "aws",
                 "google", "microsoft", "azure", "linode", "akamai", "vultr",
                 "contabo", "leaseweb", "choopa", "m247", "alibaba", "tencent")

# Addresses reserved for examples and tests, never used by real computers.
TEST_NETS = [ipaddress.ip_network(n) for n in
             ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32")]

LABELS = {
    "test": "Test address (not a real computer)",
    "local": "Device in your own network",
    "tor": "Tor network: the real location is hidden",
    "vpn": "VPN: the real location is hidden",
    "hosting": "Rented server (data center): probably not the attacker's own computer",
    "home": "Home or mobile internet: the location is probably real",
    "unknown": "Unknown (no lookup possible)",
}

_ranges = {}    # list name -> (sorted starts, ends)
_cache = {}     # ip -> result


def _lists_dir():
    return config.DATA_DIR / "lists"


def _download(urls):
    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Sentinel"})
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode(errors="replace")
        except OSError as e:
            log.info("Could not download %s: %s", url, e)
    return None


def update_lists(force=False):
    """Download the lists if they are older than a day. Returns how many
    lists are available afterwards."""
    folder = _lists_dir()
    folder.mkdir(parents=True, exist_ok=True)
    for name, urls in LISTS.items():
        path = folder / f"{name}.txt"
        if not force and path.exists() and time.time() - path.stat().st_mtime < MAX_AGE:
            continue
        text = _download(urls)
        if text and len(text) > 100:
            path.write_text(text)
    _ranges.clear()
    _cache.clear()
    return sum(1 for name in LISTS if (folder / f"{name}.txt").exists())


def _load(name):
    if name in _ranges:
        return _ranges[name]
    spans = []
    try:
        for line in (_lists_dir() / f"{name}.txt").read_text().splitlines():
            line = line.split("#")[0].strip()
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                continue
            spans.append((int(net.network_address), int(net.broadcast_address)))
    except OSError:
        pass
    spans.sort()
    merged = []  # join overlapping ranges, so each IP is in at most one
    for start, end in spans:
        if merged and start <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    _ranges[name] = ([s for s, _ in merged], [e for _, e in merged])
    return _ranges[name]


def in_list(ip, name):
    """Is the IP in one of the downloaded lists? (lists are sorted ranges)"""
    starts, ends = _load(name)
    i = bisect.bisect_right(starts, int(ip)) - 1
    return i >= 0 and int(ip) <= ends[i]


def _get_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Sentinel",
                                               "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def _abuse_emails(rdap):
    """Find the e-mail addresses of the 'abuse' contacts in an RDAP answer."""
    found = []

    def walk(entities):
        for ent in entities or []:
            if "abuse" in ent.get("roles", []):
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "email":
                        found.append(item[3])
            walk(ent.get("entities"))
    walk(rdap.get("entities"))
    return list(dict.fromkeys(found))


def lookup(ip, online=True):
    """Everything we can find out about an IP, as a dict."""
    ip = ipaddress.ip_address(ip)
    key = (str(ip), online)
    if key in _cache:
        return _cache[key]
    info = {"ip": str(ip), "kind": "unknown", "location": "", "isp": "",
            "network": "", "abuse_email": "", "looked_up": time.time()}

    if any(ip in net for net in TEST_NETS):
        info["kind"] = "test"
    elif ip.is_private or ip.is_loopback or ip.is_link_local:
        info["kind"] = "local"
    else:
        v = ip.version
        if in_list(ip, "tor"):
            info["kind"] = "tor"
        elif in_list(ip, f"vpn{v}"):
            info["kind"] = "vpn"
        elif in_list(ip, f"hosting{v}"):
            info["kind"] = "hosting"

        if online:
            try:
                geo = _get_json(f"https://ipinfo.io/{ip}/json")
                parts = [geo.get("city"), geo.get("region"), geo.get("country")]
                info["location"] = ", ".join(p for p in parts if p)
                info["isp"] = geo.get("org", "")
            except (OSError, ValueError) as e:
                log.info("Location lookup failed for %s: %s", ip, e)
            try:
                rdap = _get_json(f"https://rdap.org/ip/{ip}")
                info["network"] = rdap.get("name", "")
                info["abuse_email"] = ", ".join(_abuse_emails(rdap))
                if not info["location"] and rdap.get("country"):
                    info["location"] = rdap["country"]
            except (OSError, ValueError) as e:
                log.info("Owner lookup failed for %s: %s", ip, e)

        if info["kind"] == "unknown" and info["isp"]:
            isp = info["isp"].lower()
            info["kind"] = "hosting" if any(w in isp for w in HOSTING_WORDS) else "home"

    info["label"] = LABELS[info["kind"]]
    _cache[key] = info
    return info
