"""Settings.

Installed as a system service: /etc/sentinel/config.toml
Not installed (developing):     ~/.config/sentinel/config.toml
"""

import os
import pwd
import tomllib
from pathlib import Path

IS_ROOT = os.geteuid() == 0
SYSTEM_CONFIG_FILE = Path("/etc/sentinel/config.toml")
INSTALLED = SYSTEM_CONFIG_FILE.exists()

if IS_ROOT or INSTALLED:
    CONFIG_FILE = SYSTEM_CONFIG_FILE
    DATA_DIR = Path("/var/lib/sentinel")
    LOG_FILE = Path("/var/log/sentinel/sentinel.log")
else:
    CONFIG_FILE = Path.home() / ".config/sentinel/config.toml"
    DATA_DIR = Path.home() / ".local/share/sentinel"
    LOG_FILE = Path.home() / ".local/state/sentinel/sentinel.log"
QUARANTINE_DIR = DATA_DIR / "quarantine"
EVENTS_FILE = DATA_DIR / "events.jsonl"  # history of alarms, one JSON per line
ATTACKS_FILE = DATA_DIR / "attacks.jsonl"  # history of break-in attempts
INTEGRITY_FILE = DATA_DIR / "integrity.json"  # result of the last system check

DEFAULTS = {
    # The desktop user who gets the popups and whose files are protected.
    # Empty = whoever ran `sudo`, or the current user.
    "user": "",
    # Folders the ransomware guard protects (missing ones are skipped).
    "watch_dirs": ["~/Documents", "~/Pictures", "~/Desktop", "~/Downloads",
                   "~/Music", "~/Videos"],
    # Put trap files into the watched folders.
    "canaries": True,
    # How many changed files within `window_seconds` count as suspicious.
    "burst_files": 30,
    "window_seconds": 10,
    # Kill the guilty program automatically (otherwise: only freeze + warn).
    "auto_kill": True,
    # Move the guilty program to quarantine.
    "auto_quarantine": True,
    # Programs that are never killed (backup tools, file managers, ...).
    "allowlist": ["dolphin", "plasmashell", "baloo_file", "kio_file",
                  "kioworker", "rsync", "borg", "restic", "git", "tar",
                  "ark", "kdeconnectd", "syncthing", "nextcloud"],

    # Break-in guard
    "breakin_guard": True,
    # Block attackers in the firewall (nftables), and for how long.
    "auto_block": True,
    "block_hours": 24,
    # SSH: this many failed logins within this many minutes = attack.
    "ssh_max_failures": 5,
    "ssh_window_minutes": 10,
    # Port scan: this many different ports within this many seconds = scan.
    "scan_ports": 15,
    "scan_window_seconds": 20,
    # Look up location, provider and owner of attackers online.
    "ip_lookup": True,
    # Addresses that are never blocked (e.g. your other PCs).
    "trusted_ips": ["127.0.0.0/8", "::1/128"],

    # Credential-theft guard: warn when something reads your secrets
    # (/etc/shadow, SSH keys, WiFi passwords) or a planted decoy file.
    "credential_guard": True,
    "credential_bait": True,          # plant decoy password files as bait
    "credential_auto_kill": True,     # stop programs that touch the decoys
    "credential_auto_quarantine": True,
    "credential_readers": [],         # extra programs allowed to read secrets

    # Persistence guard: warn when something adds itself to autostart/cron/etc.
    "persistence_guard": True,

    # Crash guard (fork-bomb detector). OFF by default: compiling on Gentoo
    # starts many processes and could look like a fork bomb.
    "crash_guard": False,
    "crash_max_children": 200,

    # Gentoo: check system programs against Portage's records once a day.
    "system_check": True,
}


def load_raw(path=None):
    """Settings exactly as written in the file (missing ones from DEFAULTS)."""
    cfg = dict(DEFAULTS)
    path = path or CONFIG_FILE
    if path.exists():
        with open(path, "rb") as f:
            cfg.update(tomllib.load(f))
    return cfg


def validate(cfg):
    """Raise ValueError if a setting has the wrong type."""
    for key, value in cfg.items():
        if key not in DEFAULTS:
            raise ValueError(f"Unknown setting: {key}")
        want = type(DEFAULTS[key])
        if not isinstance(value, want) or (want is int and isinstance(value, bool)):
            raise ValueError(f"{key} must be {want.__name__}")
        if want is list and not all(isinstance(v, str) for v in value):
            raise ValueError(f"{key} must be a list of text")
        if want is int and value < 1:
            raise ValueError(f"{key} must be at least 1")


def to_toml(cfg):
    """Write settings as TOML (only handles the simple types we use)."""
    def fmt(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, str):
            return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
        return "[" + ", ".join(fmt(x) for x in v) + "]"
    lines = ["# Sentinel settings. After changing: sudo systemctl restart sentinel", ""]
    lines += [f"{key} = {fmt(cfg[key])}" for key in DEFAULTS if key in cfg]
    return "\n".join(lines) + "\n"


def load():
    cfg = load_raw()
    name = cfg["user"] or os.environ.get("SUDO_USER") or \
        (guess_desktop_user() if IS_ROOT else None) or pwd.getpwuid(os.getuid()).pw_name
    user = pwd.getpwnam(name)
    cfg["user"], cfg["uid"], cfg["home"] = user.pw_name, user.pw_uid, user.pw_dir
    cfg["watch_dirs"] = [expand(d, user.pw_dir) for d in cfg["watch_dirs"]]
    return cfg


def guess_desktop_user():
    """The only normal user account on this PC, if there is exactly one."""
    people = [u.pw_name for u in pwd.getpwall()
              if 1000 <= u.pw_uid < 60000 and u.pw_dir.startswith("/home/")]
    return people[0] if len(people) == 1 else None


def expand(folder, home):
    return Path(home + folder[1:] if folder.startswith("~") else folder)
