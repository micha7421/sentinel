"""Persistence guard.

Malware from a USB stick likes to make itself start again at every login,
by dropping a file into an autostart folder, a systemd user service, a cron
job, or by adding a line to a login script like ~/.bashrc.

This guard watches all those places and warns you the moment something new
appears there. It does not delete anything by itself (an app you just
installed may legitimately add autostart), it only tells you what changed so
you can check it.
"""

import logging
import os
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import alarms
from .notify import popup

log = logging.getLogger("sentinel")

# Login scripts: single files we watch inside the home folder.
LOGIN_SCRIPTS = [".bashrc", ".bash_profile", ".bash_login", ".profile",
                 ".zshrc", ".zprofile", ".zlogin", ".xprofile", ".xinitrc",
                 ".config/plasma-workspace/env", ".config/fish/config.fish"]


def autostart_dirs(home):
    home = Path(home)
    dirs = [home / ".config/autostart",
            home / ".config/autostart-scripts",
            home / ".config/systemd/user",
            home / ".local/share/systemd/user",
            home / ".config/plasma-workspace/env",
            home / ".config/plasma-workspace/shutdown",
            Path("/etc/xdg/autostart"),
            Path("/var/spool/cron/crontabs"),
            Path("/var/spool/cron")]
    return dirs


class PersistenceGuard(FileSystemEventHandler):
    def __init__(self, cfg, home=None, test=False):
        self.cfg = cfg
        self.home = Path(home or cfg.get("home", os.path.expanduser("~")))
        self.test = test
        self.observer = None
        self.recent = {}      # path -> time
        self.login_scripts = {}   # path -> size at startup
        self.alarm_count = 0

    def start(self):
        self.observer = Observer()
        watched = 0

        # Autostart folders (make our own if missing, so new drops are caught).
        for d in autostart_dirs(self.home):
            if not d.exists() and d.is_relative_to(self.home):
                try:
                    d.mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass
            if d.is_dir() and os.access(d, os.R_OK):
                try:
                    self.observer.schedule(self, str(d), recursive=True)
                    watched += 1
                except OSError as e:
                    log.info("Can't watch %s: %s", d, e)

        # Login scripts: watch the folders that hold them, remember their size.
        script_dirs = set()
        for rel in LOGIN_SCRIPTS:
            path = self.home / rel
            self.login_scripts[str(path)] = path.stat().st_size if path.exists() else 0
            script_dirs.add(str(path.parent))
        for d in script_dirs:
            if os.path.isdir(d):
                try:
                    self.observer.schedule(self, d, recursive=False)
                    watched += 1
                except OSError:
                    pass

        self.observer.start()
        log.info("Persistence guard watching %d locations.", watched)
        return True

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()

    def on_any_event(self, event):
        if event.event_type not in ("created", "modified", "moved"):
            return
        path = getattr(event, "dest_path", "") or event.src_path
        if event.is_directory:
            return

        known = path in self.login_scripts
        if known:
            # Only alarm if a login script actually grew (new commands added).
            size = Path(path).stat().st_size if os.path.exists(path) else 0
            if size <= self.login_scripts.get(path, 0):
                self.login_scripts[path] = size
                return
            self.login_scripts[path] = size
            what = f"A login script was changed: {path}"
        else:
            what = f"Something was added to startup: {path}"

        now = time.time()
        if now - self.recent.get(path, 0) < 5:
            return
        self.recent[path] = now

        self.alarm_count += 1
        advice = ("If you just installed a program, this is normal. If not, a "
                  "USB stick or malware may be trying to run at every login.")
        log.warning("PERSISTENCE ALARM: %s", what)
        popup("🚀 New autostart entry", what + "\n" + advice, "critical")
        alarms.record_alarm(what, [advice], kind="persistence", test=self.test)
