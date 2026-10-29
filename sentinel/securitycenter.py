"""Security center: find the security tools on this PC and show their state
in one place (and offer a few safe actions).

Each tool is probed defensively: a tool that errors or isn't installed never
breaks the others. A probe returns a dict:

    {key, name, installed, ok, state, detail, actions}

where `ok` is True (good), False (needs attention) or None (not installed /
nothing to judge), and each action is
    {label, argv, root}         # root=True runs it through pkexec
"""

import logging
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("sentinel")


def _which(*names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def _run(argv, timeout=5):
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None


def _service_state(name):
    """'active', 'inactive', 'failed', 'unknown', or 'no-systemd'."""
    if not shutil.which("systemctl"):
        return "no-systemd"
    r = _run(["systemctl", "is-active", name])
    return (r.stdout.strip() if r else "") or "unknown"


# ---------- individual tools ----------

def probe_sentinel():
    state = _service_state("sentinel")
    active = state == "active"
    return {"key": "sentinel", "name": "Sentinel", "installed": True,
            "ok": active, "state": "Protecting" if active else "Not running",
            "detail": "The background guard itself.",
            "actions": [] if active else
            [{"label": "Start", "argv": ["systemctl", "enable", "--now", "sentinel"],
              "root": True}]}


def probe_firewall():
    nft = _which("nft")
    if not nft:
        return {"key": "firewall", "name": "Firewall (nftables)", "installed": False,
                "ok": None, "state": "Not installed",
                "detail": "Install net-firewall/nftables to block attackers.",
                "actions": []}
    r = _run([nft, "list", "ruleset"])
    rules = bool(r and r.stdout.strip())
    return {"key": "firewall", "name": "Firewall (nftables)", "installed": True,
            "ok": rules, "state": "Rules active" if rules else "No rules loaded",
            "detail": "Sentinel adds its own table to block attackers."
            if rules else "No firewall rules are loaded right now.",
            "actions": []}


def probe_mullvad():
    mullvad = _which("mullvad")
    if not mullvad:
        return {"key": "mullvad", "name": "Mullvad VPN", "installed": False,
                "ok": None, "state": "Not installed", "detail": "", "actions": []}
    r = _run([mullvad, "status"])
    out = (r.stdout if r else "").strip()
    connected = out.lower().startswith("connected")
    actions = [{"label": "Disconnect", "argv": [mullvad, "disconnect"], "root": False}] \
        if connected else \
        [{"label": "Connect", "argv": [mullvad, "connect"], "root": False}]
    return {"key": "mullvad", "name": "Mullvad VPN", "installed": True,
            "ok": connected, "state": "Connected" if connected else "Disconnected",
            "detail": out.splitlines()[0] if out else "", "actions": actions}


def probe_wireguard():
    wg = _which("wg")
    if not wg:
        return {"key": "wireguard", "name": "WireGuard", "installed": False,
                "ok": None, "state": "Not installed", "detail": "", "actions": []}
    r = _run([wg, "show", "interfaces"])
    ifaces = (r.stdout.split() if r else [])
    up = bool(ifaces)
    return {"key": "wireguard", "name": "WireGuard", "installed": True,
            "ok": up, "state": "Up: " + ", ".join(ifaces) if up else "No tunnel up",
            "detail": "", "actions": []}


def probe_tor():
    if not _which("tor"):
        return {"key": "tor", "name": "Tor", "installed": False, "ok": None,
                "state": "Not installed", "detail": "", "actions": []}
    state = _service_state("tor")
    active = state == "active"
    return {"key": "tor", "name": "Tor", "installed": True, "ok": active,
            "state": "Running" if active else "Stopped", "detail": "", "actions": []}


def probe_clamav():
    if not _which("clamscan", "clamdscan"):
        return {"key": "clamav", "name": "ClamAV antivirus", "installed": False,
                "ok": None, "state": "Not installed",
                "detail": "A signature scanner that complements Sentinel's "
                          "behaviour-based guards.", "actions": []}
    # Freshness of the virus database.
    detail, ok = "", True
    db = None
    for d in ("/var/lib/clamav", "/var/db/clamav"):
        main = Path(d)
        if main.is_dir():
            sigs = list(main.glob("*.cvd")) + list(main.glob("*.cld"))
            if sigs:
                import time
                age_days = (time.time() - max(f.stat().st_mtime for f in sigs)) / 86400
                db = age_days
                detail = f"Virus database is {age_days:.0f} day(s) old."
                ok = age_days < 7
    actions = [{"label": "Update database", "argv": ["freshclam"], "root": True}]
    return {"key": "clamav", "name": "ClamAV antivirus", "installed": True,
            "ok": ok if db is not None else None,
            "state": "Installed", "detail": detail or "Installed.", "actions": actions}


def probe_sshd():
    if not _which("sshd") and not Path("/usr/sbin/sshd").exists():
        return {"key": "sshd", "name": "SSH server", "installed": False, "ok": None,
                "state": "Not installed",
                "detail": "No SSH server — nothing to attack from the network.",
                "actions": []}
    state = _service_state("sshd") if _service_state("sshd") != "unknown" \
        else _service_state("ssh")
    running = state == "active"
    pw_auth = False
    try:
        for line in Path("/etc/ssh/sshd_config").read_text().splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0].lower() == "passwordauthentication":
                pw_auth = parts[1].lower() == "yes"
    except OSError:
        pass
    if not running:
        return {"key": "sshd", "name": "SSH server", "installed": True, "ok": True,
                "state": "Stopped (safe)",
                "detail": "The SSH server is off, so nobody can log in remotely.",
                "actions": []}
    return {"key": "sshd", "name": "SSH server", "installed": True, "ok": not pw_auth,
            "state": "Running",
            "detail": "Password login is ON — guessable. Prefer keys only."
            if pw_auth else "Running with key-only login (good).",
            "actions": []}


def probe_disk_encryption():
    r = _run(["lsblk", "-rno", "TYPE"])
    if not r:
        return None
    encrypted = "crypt" in r.stdout.split()
    return {"key": "luks", "name": "Disk encryption", "installed": True,
            "ok": encrypted,
            "state": "On" if encrypted else "Off",
            "detail": "Your disk is encrypted (LUKS)." if encrypted else
            "No encrypted volume found. A thief with the disk can read it.",
            "actions": []}


PROBES = [probe_sentinel, probe_firewall, probe_mullvad, probe_wireguard,
          probe_tor, probe_clamav, probe_sshd, probe_disk_encryption]


def collect():
    tools = []
    for probe in PROBES:
        try:
            t = probe()
            if t:
                tools.append(t)
        except Exception as e:  # one broken probe must not break the page
            log.error("Security center probe %s failed: %s", probe.__name__, e)
    return tools
