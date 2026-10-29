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


def probe_apparmor():
    if not (shutil.which("aa-status") or Path("/sys/kernel/security/apparmor").exists()):
        return None
    r = _run(["aa-status", "--enabled"])
    enabled = r is not None and r.returncode == 0
    return {"key": "apparmor", "name": "AppArmor", "installed": True, "ok": enabled,
            "state": "Enforcing" if enabled else "Off",
            "detail": "Confines programs so a break-in does less damage."
            if enabled else "Installed but not enabled.", "actions": []}


def probe_selinux():
    if not shutil.which("getenforce"):
        return None
    r = _run(["getenforce"])
    mode = (r.stdout.strip() if r else "") or "Unknown"
    return {"key": "selinux", "name": "SELinux", "installed": True,
            "ok": mode == "Enforcing", "state": mode,
            "detail": "Confines programs (enforcing is best)." if mode != "Disabled"
            else "Installed but disabled.", "actions": []}


def probe_fail2ban():
    if not _which("fail2ban-client"):
        return None
    active = _service_state("fail2ban") == "active"
    return {"key": "fail2ban", "name": "Fail2ban", "installed": True, "ok": active,
            "state": "Running" if active else "Stopped",
            "detail": "Bans repeat attackers (Sentinel's break-in guard does this too).",
            "actions": []}


def probe_firewalld():
    if not _which("firewall-cmd"):
        return None
    active = _service_state("firewalld") == "active"
    return {"key": "firewalld", "name": "firewalld", "installed": True, "ok": active,
            "state": "Running" if active else "Stopped", "detail": "", "actions": []}


def probe_ufw():
    if not _which("ufw"):
        return None
    r = _run(["ufw", "status"])
    active = r is not None and "Status: active" in (r.stdout or "")
    return {"key": "ufw", "name": "UFW firewall", "installed": True, "ok": active,
            "state": "Active" if active else "Inactive", "detail": "", "actions": []}


PROBES = [probe_sentinel, probe_firewall, probe_firewalld, probe_ufw,
          probe_mullvad, probe_wireguard, probe_tor, probe_clamav, probe_fail2ban,
          probe_apparmor, probe_selinux, probe_sshd, probe_disk_encryption]


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


# ---------- hardening score ----------

def score(cfg, tools=None):
    """A 0-100 hardening score plus the top things to fix.

    Each check has a weight; checks that don't apply (a tool that isn't
    installed) are left out of the total, so the score reflects this PC.
    """
    tools = tools if tools is not None else collect()
    by_key = {t["key"]: t for t in tools}

    def tool_ok(key):
        t = by_key.get(key)
        return None if (t is None or t["ok"] is None) else t["ok"]

    # (label, weight, passed(True/False/None=n/a), how-to-fix)
    checks = [
        ("Sentinel is running", 3, tool_ok("sentinel"),
         "Start it: systemctl enable --now sentinel"),
        ("Ransomware guard is on", 2, True, "Turn it on in Settings."),
        ("Break-in guard is on", 1, cfg.get("breakin_guard"),
         "Turn on the break-in guard in Settings."),
        ("Credential guard is on", 2, cfg.get("credential_guard"),
         "Turn on the credential guard in Settings."),
        ("Persistence guard is on", 1, cfg.get("persistence_guard"),
         "Turn on the autostart guard in Settings."),
        ("A firewall is active", 2,
         _any(tool_ok("firewall"), tool_ok("firewalld"), tool_ok("ufw")),
         "Load firewall rules (nftables/firewalld/ufw)."),
        ("Daily system file check is on", 1, cfg.get("system_check") if packages_ok() else None,
         "Turn on the system file check in Settings."),
        ("Package scanning is on", 1, cfg.get("package_scan") if _which("pacman") else None,
         "Turn on package scanning in Settings."),
        ("Disk is encrypted", 3, tool_ok("luks"),
         "Encrypting the disk needs a reinstall with LUKS; plan for it."),
        ("SSH is safe", 2, tool_ok("sshd"),
         "Turn off SSH password login (keys only) or stop the SSH server."),
        ("Virus database is fresh", 1, tool_ok("clamav"),
         "Update ClamAV: run freshclam."),
        ("A sandbox (AppArmor/SELinux) is on", 1,
         _any(tool_ok("apparmor"), tool_ok("selinux")),
         "Enable AppArmor or SELinux for extra isolation."),
    ]

    total = got = 0
    recommendations = []
    for label, weight, passed, how in checks:
        if passed is None:
            continue
        total += weight
        if passed:
            got += weight
        else:
            recommendations.append({"text": label.replace(" is ", " is not ")
                                    .replace("is safe", "is not locked down")
                                    .replace("A firewall is not active", "No firewall is active"),
                                    "how": how, "weight": weight})
    recommendations.sort(key=lambda r: r["weight"], reverse=True)
    value = round(100 * got / total) if total else 100
    return {"score": value, "recommendations": recommendations}


def _any(*vals):
    """True if any is True, False if all are False, None if all are n/a."""
    real = [v for v in vals if v is not None]
    if not real:
        return None
    return any(real)


def packages_ok():
    from . import packages
    return packages.available()
