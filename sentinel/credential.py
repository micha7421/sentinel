"""Credential-theft guard.

Catches a program that reads your secrets: password hashes (/etc/shadow),
SSH private keys, saved WiFi passwords (NetworkManager), and decoy
"password" files we plant as bait.

How: the Linux fanotify feature tells us, in real time, which process opens
a watched file. Normal programs that are expected to read a given secret
(e.g. ssh reading your SSH key) are ignored; anyone else raises the alarm.

The bait files have no legitimate reader at all, so touching one is a very
strong sign of a thief, and that case can be stopped automatically.

Needs root (to watch /etc/shadow and to see other processes).
"""

import ctypes
import logging
import os
import struct
import threading
import time
from pathlib import Path

import psutil

from . import alarms, quarantine
from .notify import popup

log = logging.getLogger("sentinel")

# fanotify constants
FAN_CLOEXEC = 0x1
FAN_CLASS_NOTIF = 0x0
FAN_MARK_ADD = 0x1
FAN_OPEN = 0x20
AT_FDCWD = -100
EVENT = struct.Struct("=IBBHQii")  # len, vers, reserved, meta_len, mask, fd, pid

_libc = ctypes.CDLL(None, use_errno=True)
_libc.fanotify_init.argtypes = [ctypes.c_uint, ctypes.c_uint]
_libc.fanotify_mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64,
                                ctypes.c_int, ctypes.c_char_p]

# Processes that legitimately read many files (indexers, backups). They are
# allowed to touch any watched file, including the bait.
SYSTEM_READERS = {"baloo_file", "baloo", "tracker-miner-f", "tracker-extract",
                  "updatedb", "mlocate", "locate", "plocate", "rsync", "borg",
                  "restic", "tar", "duplicity", "rclone", "clamd", "clamscan",
                  "freshclam"}

# Expected readers for each kind of real secret.
SHADOW_READERS = {"unix_chkpwd", "passwd", "chpasswd", "sudo", "sudo.real",
                  "su", "login", "sshd", "sshd-session", "systemd",
                  "systemd-logind", "systemd-user", "gdm", "sddm", "sddm-helper",
                  "lightdm", "agetty", "useradd", "usermod", "userdel", "vipw",
                  "faillock", "pam_tally2", "polkitd", "accounts-daemon",
                  "gkr-pam", "gnome-keyring-d"}
SSH_READERS = {"ssh", "sshd", "sshd-session", "ssh-agent", "ssh-add",
               "ssh-keygen", "scp", "sftp", "sftp-server", "git", "git-remote-ssh",
               "rsync", "mosh", "mosh-server", "gpg-agent", "keychain",
               "gnome-keyring-d", "kwalletd5", "kwalletd6", "ansible"}
NM_READERS = {"NetworkManager", "nm-online", "nm-applet", "wpa_supplicant"}

BAIT_PRIVATE_KEY = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
RECOY-SENTINEL-BAIT-FILE-DO-NOT-USE-THIS-IS-NOT-A-REAL-KEY-aaaaaaaaaaaa
-----END OPENSSH PRIVATE KEY-----
"""
BAIT_PASSWORDS = """# Saved passwords (KeePass export)
email: hunter2
bank: Tr0ub4dor&3
wifi "FRITZ!Box 7590": correct-horse-battery-staple
"""


def friendly(path):
    if path == "/etc/shadow":
        return "/etc/shadow (everyone's password hashes)"
    if "NetworkManager" in path:
        return f"{path} (a saved WiFi password)"
    if "/.ssh/" in path:
        return f"{path} (an SSH private key)"
    return path


class CredentialGuard:
    def __init__(self, cfg, home=None, watch=None, test=False):
        self.cfg = cfg
        self.home = Path(home or cfg.get("home", os.path.expanduser("~")))
        self.test = test
        self.readers = SYSTEM_READERS | set(cfg.get("credential_readers", []))
        self.watched = {}   # path -> set of allowed reader names ("" set = bait)
        self.bait = set()   # paths of our decoy files
        self.fd = None
        self.pid = os.getpid()
        self.recent = {}    # (pid, path) -> time, to avoid repeat alarms
        self.stop_event = threading.Event()
        self.alarm_count = 0
        self._custom_watch = watch

    # ---------- what to watch ----------

    def build_watch(self):
        watch = {}
        if self._custom_watch is not None:
            return dict(self._custom_watch)
        if os.path.exists("/etc/shadow"):
            watch["/etc/shadow"] = SHADOW_READERS
        nm = Path("/etc/NetworkManager/system-connections")
        if nm.is_dir():
            for f in nm.glob("*"):
                if f.is_file():
                    watch[str(f)] = NM_READERS
        ssh = self.home / ".ssh"
        if ssh.is_dir():
            for f in ssh.glob("id_*"):
                if f.is_file() and not f.name.endswith(".pub"):
                    watch[str(f)] = SSH_READERS
        return watch

    def place_bait(self):
        """Drop decoy secrets where a thief would look. No real program reads
        them, so any access is almost certainly malware."""
        if not self.cfg.get("credential_bait", True):
            return
        spots = []
        ssh = self.home / ".ssh"
        if ssh.is_dir():
            spots.append((ssh / "id_rsa.old", BAIT_PRIVATE_KEY))  # not a default ssh name
        docs = self.home / "Documents"
        spots.append(((docs if docs.is_dir() else self.home) / "passwords.txt",
                      BAIT_PASSWORDS))
        spots.append((self.home / ".credentials.bak", BAIT_PASSWORDS))
        for path, content in spots:
            try:
                path.write_text(content)
                os.chmod(path, 0o600)
                self.bait.add(str(path))
                self.watched[str(path)] = set()  # nobody is allowed to read bait
            except OSError as e:
                log.info("Could not place bait %s: %s", path, e)

    def remove_bait(self):
        for path in self.bait:
            try:
                Path(path).unlink(missing_ok=True)
            except OSError:
                pass

    # ---------- start / stop ----------

    def start(self):
        fd = _libc.fanotify_init(FAN_CLOEXEC | FAN_CLASS_NOTIF,
                                 os.O_RDONLY | os.O_LARGEFILE)
        if fd < 0:
            log.warning("Credential guard needs root (fanotify: %s).",
                        os.strerror(ctypes.get_errno()))
            return False
        self.fd = fd
        self.watched.update(self.build_watch())
        self.place_bait()
        marked = sum(self.mark(p) for p in list(self.watched))
        threading.Thread(target=self._loop, daemon=True).start()
        log.info("Credential guard watching %d files (%d bait).", marked, len(self.bait))
        return True

    def mark(self, path):
        if _libc.fanotify_mark(self.fd, FAN_MARK_ADD, ctypes.c_uint64(FAN_OPEN),
                               AT_FDCWD, path.encode()) < 0:
            err = ctypes.get_errno()
            if err != 2:  # ENOENT: file vanished, ignore
                log.info("Could not watch %s: %s", path, os.strerror(err))
            return False
        return True

    def stop(self):
        self.stop_event.set()
        self.remove_bait()
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError:
                pass

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                buf = os.read(self.fd, 16 * EVENT.size)
            except OSError:
                return
            offset = 0
            while offset + EVENT.size <= len(buf):
                length, _, _, _, _, efd, pid = EVENT.unpack_from(buf, offset)
                offset += length
                if efd < 0:
                    continue
                try:
                    path = os.readlink(f"/proc/self/fd/{efd}")
                finally:
                    os.close(efd)
                if pid != self.pid and path in self.watched:
                    self.on_open(path, pid)

    # ---------- reaction ----------

    def on_open(self, path, pid):
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except psutil.Error:
            name = "a program that already exited"
            proc = None

        allowed = self.watched.get(path, set())
        if name in self.readers or name in allowed:
            return  # an expected reader, fine

        now = time.time()
        if now - self.recent.get((pid, path), 0) < 10:
            return
        self.recent[(pid, path)] = now

        bait = path in self.bait
        self.alarm_count += 1
        actions = []
        if bait and self.cfg.get("credential_auto_kill", True) and proc:
            actions.append(self.stop_thief(proc))
        else:
            actions.append("Only warned, not stopped. If this wasn't you, "
                           "disconnect from the internet and change your passwords.")

        what = "a decoy password file" if bait else friendly(path)
        reason = f"'{name}' (PID {pid}) read {what}"
        log.warning("CREDENTIAL ALARM: %s", reason)
        popup("🔑 Someone is reading your secrets!", reason + "\n" + "\n".join(actions),
              "critical")
        alarms.record_alarm(reason, actions, kind="credential", test=self.test)

    def stop_thief(self, proc):
        try:
            name, pid = proc.name(), proc.pid
            exe, cmdline = proc.exe(), proc.cmdline()
            proc.kill()
        except psutil.Error as e:
            return f"Could not stop the program: {e}"
        line = f"Stopped '{name}' (PID {pid})."
        if self.cfg.get("credential_auto_quarantine", True):
            for f in quarantine.files_to_quarantine(exe, cmdline):
                try:
                    item = quarantine.quarantine(f, "read a decoy password file")
                    line += f"\nQuarantined {f} (id: {item})"
                except OSError as e:
                    line += f"\nCould not quarantine {f}: {e}"
        return line
