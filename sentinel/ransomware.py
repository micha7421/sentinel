"""Ransomware guard.

How it spots ransomware:
  1. Trap files ("canaries") are placed in protected folders. Normal programs
     never touch them; ransomware encrypts everything, including them.
  2. Many files changing in a short time AND the new content looks random
     (encrypted), or files get renamed to strange extensions like .locked.
  3. Ransom notes appearing (HOW_TO_DECRYPT.txt and similar).

What it does then: freezes and kills the guilty program, quarantines it,
and shows a popup.
"""

import collections
import hashlib
import json
import logging
import math
import os
import re
import threading
import time
from pathlib import Path

import psutil
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from . import config, packages, quarantine
from .notify import popup
from .tracker import WriteTracker

log = logging.getLogger("sentinel")

CANARY_NAME = "!sentinel-trap-do-not-touch.docx"
CANARY_TEXT = ("This is a trap file made by Sentinel to catch ransomware.\n"
               "Please leave it alone. It disappears when Sentinel stops.\n") * 40

# File types that are already compressed, so random-looking content is normal.
COMPRESSED = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".mp3",
              ".ogg", ".flac", ".m4a", ".mp4", ".mkv", ".webm", ".avi",
              ".mov", ".zip", ".gz", ".xz", ".bz2", ".zst", ".7z", ".rar",
              ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".pdf",
              ".epub", ".jar", ".apk", ".iso", ".gpg", ".age", ".part",
              ".crdownload", ".tbz2", ".gpkg", ".xpak"}

RANSOM_NOTE = re.compile(
    r"(decrypt|recover|restore|ransom|how.?to|unlock).*\.(txt|html?|hta)$",
    re.IGNORECASE)


def entropy(path, size=4096):
    """How random a file looks: ~4-5 for text, close to 8.0 for encrypted."""
    try:
        with open(path, "rb") as f:
            data = f.read(size)
    except OSError:
        return 0.0
    if len(data) < 256:
        return 0.0
    counts = collections.Counter(data)
    return -sum(c / len(data) * math.log2(c / len(data)) for c in counts.values())


def is_inside(path, folders):
    return any(str(path).startswith(str(d) + os.sep) for d in folders)


class RansomwareGuard(FileSystemEventHandler):
    def __init__(self, cfg, watch_dirs=None, test=False):
        self.cfg = cfg
        self.test = test
        self.dirs = [d for d in (watch_dirs or cfg["watch_dirs"]) if d.is_dir()]
        self.events = collections.deque()  # (time, path, kind)
        self.canaries = {}  # path -> sha256 of the content
        self.lock = threading.Lock()
        self.last_alarm = 0.0
        self.observer = None
        self.tracker = None
        self.alarm_count = 0  # used by the self-test

    # ---------- trap files ----------

    def place_canaries(self):
        if not self.cfg["canaries"]:
            return
        digest = hashlib.sha256(CANARY_TEXT.encode()).hexdigest()
        for d in self.dirs:
            path = d / CANARY_NAME
            try:
                path.write_text(CANARY_TEXT)
                self.canaries[str(path)] = digest
            except OSError as e:
                log.error("Could not place trap file in %s: %s", d, e)

    def canary_damaged(self, path):
        """True if a trap file was deleted, moved or its content changed."""
        try:
            data = Path(path).read_bytes()
        except OSError:
            return True
        return hashlib.sha256(data).hexdigest() != self.canaries[path]

    def remove_canaries(self):
        for path in self.canaries:
            Path(path).unlink(missing_ok=True)
        self.canaries.clear()

    # ---------- start / stop ----------

    def start(self):
        if not self.dirs:
            log.error("No folders to protect, check watch_dirs in the config.")
            return
        tracker = WriteTracker(self.dirs, keep_seconds=self.cfg["window_seconds"])
        if tracker.start():
            self.tracker = tracker
        self.place_canaries()
        self.observer = Observer()
        for d in self.dirs:
            self.observer.schedule(self, str(d), recursive=True)
        self.observer.start()
        log.info("Ransomware guard protecting: %s",
                 ", ".join(str(d) for d in self.dirs))

    def stop(self):
        if self.observer:
            self.observer.stop()
            self.observer.join()
        self.remove_canaries()

    # ---------- file events ----------

    def on_any_event(self, event):
        if event.is_directory or event.event_type in ("opened", "closed_no_write"):
            return
        src = event.src_path
        dest = getattr(event, "dest_path", "") or ""

        with self.lock:
            # Anything touching a trap file is an instant alarm.
            for p in (src, dest):
                if p in self.canaries and self.canary_damaged(p):
                    self.alarm(f"A trap file was {event.event_type}: {p}")
                    return

            now = time.time()
            path = dest or src
            self.events.append((now, path, event.event_type, src))
            while self.events and self.events[0][0] < now - self.cfg["window_seconds"]:
                self.events.popleft()

            reason = self.check_burst()
            if reason:
                self.alarm(reason)

    def check_burst(self):
        changed = {p for _, p, kind, _ in self.events if kind != "deleted"}
        if len(changed) < self.cfg["burst_files"]:
            return None

        notes = [p for p in changed if RANSOM_NOTE.search(os.path.basename(p))]
        renamed = 0
        for _, dest, kind, src in self.events:
            if kind == "moved":
                old, new = Path(src).suffix.lower(), Path(dest).suffix.lower()
                if new and new != old and new not in COMPRESSED:
                    renamed += 1

        # Only check content of file types that are normally not random.
        sample = [p for p in list(changed)[-40:]
                  if Path(p).suffix.lower() not in COMPRESSED and os.path.isfile(p)]
        random_looking = sum(1 for p in sample if entropy(p) > 7.5)

        if renamed >= 10:
            return f"{len(changed)} files changed, {renamed} renamed to strange extensions"
        if sample and random_looking >= len(sample) / 2:
            return f"{len(changed)} files changed and their content looks encrypted"
        if len(notes) >= 2:
            return f"{len(changed)} files changed and ransom notes appeared"
        return None

    # ---------- reaction ----------

    def alarm(self, reason):
        if time.time() - self.last_alarm < 5:
            return  # already handling it
        self.last_alarm = time.time()
        self.alarm_count += 1
        log.warning("RANSOMWARE ALARM: %s", reason)

        suspects = self.find_suspects()
        if not suspects:
            popup("⚠️ Possible ransomware!",
                  f"{reason}\nCould not find which program did it. "
                  "If you didn't do this yourself, turn off your PC's network.",
                  "critical")
            self.record(reason, ["Could not find which program did it."])
            return

        report = []
        for proc in suspects:
            report.append(self.handle_suspect(proc, reason))

        self.record(reason, report)
        popup("🛑 Ransomware stopped!", reason + "\n\n" + "\n".join(report),
              "critical")
        self.events.clear()
        self.place_canaries()  # replace damaged traps

    def record(self, reason, actions):
        """Save the alarm in the history file the window shows."""
        entry = {"time": time.time(), "reason": reason, "actions": actions,
                 "test": self.test}
        try:
            config.DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(config.EVENTS_FILE, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError as e:
            log.error("Could not save alarm history: %s", e)

    def find_suspects(self):
        found = self.suspects_from_tracker() if self.tracker else self.guess_suspects()
        # Freeze them right away so they stop encrypting.
        for p in found:
            try:
                p.suspend()
            except psutil.Error:
                pass
        return found

    def suspects_from_tracker(self):
        """Programs that wrote a trap file or many files just now."""
        time.sleep(0.3)  # let the newest write events arrive
        allow = set(self.cfg["allowlist"])
        window = self.cfg["window_seconds"]
        counts = self.tracker.writers(window)
        trap_writers = self.tracker.writers(window, set(self.canaries))
        found = []
        for pid, n in counts.items():
            if pid in trap_writers or n >= 3:
                try:
                    p = psutil.Process(pid)
                    if pid > 1 and p.name() not in allow:
                        found.append(p)
                except psutil.Error:
                    pass
        return found

    def guess_suspects(self):
        """Without fanotify: look for our own user's programs that have
        files open in protected folders."""
        me, my_pid = os.getuid(), os.getpid()
        allow = set(self.cfg["allowlist"])
        found = {}

        def candidates():
            for p in psutil.process_iter(["pid", "name", "uids"]):
                if p.pid == my_pid or p.info["uids"] is None:
                    continue
                if p.info["uids"].real != me or p.info["name"] in allow:
                    continue
                yield p

        # Ransomware opens files constantly, so check a few times quickly.
        for _ in range(8):
            for p in candidates():
                try:
                    files = p.open_files()
                    cwd = p.cwd()
                except (psutil.Error, OSError):
                    continue
                if any(is_inside(f.path, self.dirs) for f in files) or \
                        (is_inside(cwd + os.sep + "x", self.dirs) and
                         p.io_counters().write_bytes > 0):
                    found[p.pid] = p
            time.sleep(0.1)
        return list(found.values())

    def handle_suspect(self, proc, reason):
        try:
            name, pid = proc.name(), proc.pid
            exe, cmdline = proc.exe(), proc.cmdline()
        except psutil.Error:
            return "A suspicious program exited by itself."

        if not self.cfg["auto_kill"]:
            return f"Program '{name}' (PID {pid}) is FROZEN. Kill it with: kill -9 {pid}"

        try:
            proc.kill()
        except psutil.Error as e:
            return f"Could not kill '{name}' (PID {pid}): {e}"
        line = f"Killed '{name}' (PID {pid})."

        # Ransomware sometimes uses normal tools (like gpg) to do its work,
        # or replaces a system program. Gentoo's package database tells us.
        genuine = packages.is_genuine(exe) if exe else None
        if genuine and genuine[1]:
            line += (f"\n'{name}' is a normal program from {genuine[0]}. If you "
                     "were using it yourself, add it to the trusted programs.")
        elif genuine:
            line += (f"\nWARNING: {exe} was CHANGED since {genuine[0]} installed it! "
                     f"Reinstall it with: emerge -1 {genuine[0]}")

        if self.cfg["auto_quarantine"]:
            for path in quarantine.files_to_quarantine(exe, cmdline):
                try:
                    item = quarantine.quarantine(path, reason)
                    line += f"\nQuarantined {path} (id: {item})"
                except OSError as e:
                    line += f"\nCould not quarantine {path}: {e}"
        return line
