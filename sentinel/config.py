"""Settings.

As a system service (root): /etc/sentinel/config.toml
As a normal user:           ~/.config/sentinel/config.toml
"""

import os
import pwd
import tomllib
from pathlib import Path

IS_ROOT = os.geteuid() == 0

if IS_ROOT:
    CONFIG_FILE = Path("/etc/sentinel/config.toml")
    DATA_DIR = Path("/var/lib/sentinel")
    LOG_FILE = Path("/var/log/sentinel/sentinel.log")
else:
    CONFIG_FILE = Path.home() / ".config/sentinel/config.toml"
    DATA_DIR = Path.home() / ".local/share/sentinel"
    LOG_FILE = Path.home() / ".local/state/sentinel/sentinel.log"
QUARANTINE_DIR = DATA_DIR / "quarantine"

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
}


def load():
    cfg = dict(DEFAULTS)
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "rb") as f:
            cfg.update(tomllib.load(f))

    name = cfg["user"] or os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    user = pwd.getpwnam(name)
    cfg["user"], cfg["uid"], cfg["home"] = user.pw_name, user.pw_uid, user.pw_dir

    def expand(d):
        return Path(user.pw_dir + d[1:] if d.startswith("~") else d)
    cfg["watch_dirs"] = [expand(d) for d in cfg["watch_dirs"]]
    return cfg
