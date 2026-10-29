"""Tracks WHICH program writes WHICH file, using the Linux fanotify feature.

Needs root. Without root Sentinel still detects ransomware, but has to
guess which program is guilty.
"""

import collections
import ctypes
import logging
import os
import struct
import threading
import time

log = logging.getLogger("sentinel")

FAN_CLOEXEC = 0x1
FAN_CLASS_NOTIF = 0x0
FAN_MARK_ADD = 0x1
FAN_MARK_MOUNT = 0x10
FAN_MODIFY = 0x2
FAN_CLOSE_WRITE = 0x8
AT_FDCWD = -100

# struct fanotify_event_metadata: event_len, vers, reserved, metadata_len,
# mask, fd, pid
EVENT = struct.Struct("=IBBHQii")

_libc = ctypes.CDLL(None, use_errno=True)
_libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
_libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                ctypes.c_int, ctypes.c_char_p]


class WriteTracker:
    def __init__(self, folders, keep_seconds=30):
        self.folders = [str(f) + os.sep for f in folders]
        self.keep = keep_seconds
        self.writes = collections.deque()  # (time, pid, path)
        self.lock = threading.Lock()
        self.fd = None

    def start(self):
        """Returns False if fanotify isn't available (e.g. not root)."""
        fd = _libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF,
                                 os.O_RDONLY | os.O_LARGEFILE)
        if fd < 0:
            log.info("fanotify not available (%s), will guess culprits instead.",
                     os.strerror(ctypes.get_errno()))
            return False
        for folder in self.folders:
            if _libc.fanotify_mark(fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
                                   FAN_MODIFY | FAN_CLOSE_WRITE, AT_FDCWD,
                                   folder.encode()) < 0:
                log.error("fanotify could not watch %s: %s", folder,
                          os.strerror(ctypes.get_errno()))
        self.fd = fd
        threading.Thread(target=self._loop, daemon=True).start()
        return True

    def _loop(self):
        my_pid = os.getpid()
        while True:
            try:
                buf = os.read(self.fd, 4096 * EVENT.size)
            except OSError:
                return
            offset = 0
            while offset + EVENT.size <= len(buf):
                length, _, _, _, _, fd, pid = EVENT.unpack_from(buf, offset)
                offset += length
                if fd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{fd}")
                finally:
                    os.close(fd)
                if pid != my_pid and any(path.startswith(f) for f in self.folders):
                    self._record(pid, path)

    def _record(self, pid, path):
        now = time.time()
        with self.lock:
            self.writes.append((now, pid, path))
            while self.writes and self.writes[0][0] < now - self.keep:
                self.writes.popleft()

    def writers(self, seconds, paths=None):
        """{pid: number of different files written} in the last `seconds`.
        With `paths`, only count writes to those files."""
        since = time.time() - seconds
        files = collections.defaultdict(set)
        with self.lock:
            for t, pid, path in self.writes:
                if t >= since and (paths is None or path in paths):
                    files[pid].add(path)
        return {pid: len(f) for pid, f in files.items()}
