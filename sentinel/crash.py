"""Crash guard (fork-bomb detector).

A classic "crash the PC" trick is a fork bomb: a tiny program that copies
itself over and over until the machine runs out of processes and freezes.
It shows up as one parent suddenly having hundreds of identical children.

This is OFF by default, because compiling software on Gentoo also starts
many processes at once and would look similar. Turn it on if you don't
compile much, or raise the limit.

When it fires it freezes the whole family of runaway processes (SIGSTOP),
which stops the bomb without killing your session, and warns you so you can
finish them off.
"""

import collections
import logging
import os
import signal
import threading
import time

import psutil

from . import alarms
from .notify import popup

log = logging.getLogger("sentinel")

# Programs that legitimately start lots of short-lived children.
BUILD_TOOLS = {"make", "ninja", "cc1", "cc1plus", "gcc", "g++", "clang",
               "rustc", "cargo", "emerge", "ebuild", "sandbox", "python",
               "python3", "ld", "as", "collect2", "bash", "sh", "cmake",
               "portageq", "pytest", "node", "npm"}


class CrashGuard:
    def __init__(self, cfg, test=False):
        self.cfg = cfg
        self.test = test
        self.limit = cfg.get("crash_max_children", 200)
        self.stop_event = threading.Event()
        self.handled = {}   # parent pid -> time
        self.alarm_count = 0

    def start(self):
        threading.Thread(target=self._loop, daemon=True).start()
        log.info("Crash guard running (limit %d children).", self.limit)
        return True

    def stop(self):
        self.stop_event.set()

    def _loop(self):
        while not self.stop_event.wait(1.0):
            try:
                self.check()
            except Exception as e:  # never let the watchdog thread die
                log.error("Crash guard error: %s", e)

    def check(self):
        me = os.getuid()
        children = collections.defaultdict(list)  # ppid -> [(pid, name)]
        for p in psutil.process_iter(["pid", "ppid", "name", "uids"]):
            info = p.info
            if info["uids"] and info["uids"].real == me:
                children[info["ppid"]].append((info["pid"], info["name"]))

        for ppid, kids in children.items():
            # Never freeze PID 1 or Sentinel's own process tree.
            if len(kids) < self.limit or ppid <= 1 or ppid == os.getpid():
                continue
            names = collections.Counter(n for _, n in kids)
            top_name, top_count = names.most_common(1)[0]
            # A fork bomb is many identical children; a build is a mix.
            if top_count < self.limit or top_name in BUILD_TOOLS:
                continue
            if time.time() - self.handled.get(ppid, 0) < 30:
                continue
            self.handled[ppid] = time.time()
            self.react(ppid, top_name, top_count, [pid for pid, _ in kids])

    def react(self, ppid, name, count, pids):
        self.alarm_count += 1
        frozen = 0
        for pid in [ppid] + pids:
            try:
                os.kill(pid, signal.SIGSTOP)
                frozen += 1
            except OSError:
                pass
        reason = f"Fork bomb: '{name}' made {count} copies of itself (PID {ppid})"
        action = (f"Froze {frozen} runaway processes so your PC stays usable. "
                  f"End them with:  kill -9 -{ppid}  (then check what started it).")
        log.warning("CRASH ALARM: %s", reason)
        popup("💥 Fork bomb stopped!", reason + "\n" + action, "critical")
        alarms.record_alarm(reason, [action], kind="crash", test=self.test)
