"""Break-in guard.

Notices two kinds of attacks:
  - SSH password guessing (from the system log)
  - port scans: someone knocking on many network "doors" (ports) to find
    a way in (by watching incoming connection attempts)

Then it blocks the attacker in the firewall, finds out who is behind the
IP (VPN? Tor? home internet?) and shows a popup.

Note: a home PC behind a router normally can't be reached from the
internet at all, so you will mostly see attacks from your own network.
"""

import collections
import ctypes
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import struct
import subprocess
import threading
import time

import psutil

from . import config, firewall, ipintel
from .notify import popup

log = logging.getLogger("sentinel")

# ---------- SSH password guessing ----------

SSH_FAILURE = re.compile(
    r"(?:Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(?P<user>\S+)"
    r"|Invalid user (?P<user2>\S*)) from (?P<ip>[0-9A-Fa-f.:]+)")


def parse_ssh_line(line):
    """'Failed password for root from 1.2.3.4 port 22 ssh2' -> ('1.2.3.4', 'root')"""
    m = SSH_FAILURE.search(line)
    if not m:
        return None
    try:
        ip = str(ipaddress.ip_address(m.group("ip")))
    except ValueError:
        return None
    return ip, m.group("user") or m.group("user2") or "?"


def follow_ssh_log(on_line, stop):
    """Feed every new sshd log line to on_line()."""
    if shutil.which("journalctl"):
        cmd = ["journalctl", "-f", "-n", "0", "-o", "json",
               "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sshd-session"]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        for raw in proc.stdout:
            if stop.is_set():
                break
            try:
                on_line(json.loads(raw).get("MESSAGE", ""))
            except (ValueError, TypeError):
                pass
        proc.kill()
        return
    # OpenRC systems without systemd: read the syslog file.
    for path in ("/var/log/auth.log", "/var/log/messages"):
        if os.path.exists(path):
            with open(path, errors="replace") as f:
                f.seek(0, os.SEEK_END)
                while not stop.is_set():
                    line = f.readline()
                    if not line:
                        time.sleep(1)
                    elif "sshd" in line:
                        on_line(line)
            return
    log.info("No system log found, SSH guard is off.")


# ---------- port scans ----------

# A tiny filter program that runs inside the kernel and only lets through
# incoming TCP connection attempts (SYN without ACK), for IPv4 and IPv6.
# That way Python only sees a few packets, not all your network traffic.
_BPF = [
    (0x20, 0, 0, 0xfffff004),   # 0  A = packet type
    (0x15, 0, 16, 0),           # 1  for us (PACKET_HOST)?        else drop
    (0x28, 0, 0, 0xfffff000),   # 2  A = protocol
    (0x15, 0, 7, 0x0800),       # 3  IPv4?                        else -> 11
    (0x30, 0, 0, 9),            # 4  A = IP protocol
    (0x15, 0, 12, 6),           # 5  TCP?                         else drop
    (0x28, 0, 0, 6),            # 6  A = fragment offset
    (0x45, 10, 0, 0x1fff),      # 7  fragment?                    -> drop
    (0xb1, 0, 0, 0),            # 8  X = IP header length
    (0x50, 0, 0, 13),           # 9  A = TCP flags
    (0x05, 0, 0, 4),            # 10 jump to flag check (15)
    (0x15, 0, 6, 0x86dd),       # 11 IPv6?                        else drop
    (0x30, 0, 0, 6),            # 12 A = next header
    (0x15, 0, 4, 6),            # 13 TCP?                         else drop
    (0x30, 0, 0, 53),           # 14 A = TCP flags
    (0x54, 0, 0, 0x12),         # 15 A &= SYN|ACK
    (0x15, 0, 1, 0x02),         # 16 only SYN?                    else drop
    (0x06, 0, 0, 128),          # 17 keep (first 128 bytes)
    (0x06, 0, 0, 0),            # 18 drop
]


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


def open_syn_socket():
    """A raw socket that receives incoming connection attempts (needs root)."""
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    prog = (_SockFilter * len(_BPF))(*[_SockFilter(*i) for i in _BPF])
    fprog = struct.pack("@HP", len(_BPF), ctypes.addressof(prog))
    sock.setsockopt(socket.SOL_SOCKET, 26, fprog)  # 26 = SO_ATTACH_FILTER (kernel copies it)
    return sock


def parse_syn(packet):
    """Network packet -> (source ip, destination port), or None."""
    version = packet[0] >> 4
    if version == 4 and len(packet) >= 20:
        ihl = (packet[0] & 0x0F) * 4
        if len(packet) < ihl + 4:
            return None
        src = socket.inet_ntop(socket.AF_INET, packet[12:16])
        port = struct.unpack("!H", packet[ihl + 2:ihl + 4])[0]
        return src, port
    if version == 6 and len(packet) >= 44:
        src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
        port = struct.unpack("!H", packet[42:44])[0]
        return src, port
    return None


# ---------- the guard ----------

def own_addresses():
    addrs = set()
    for entries in psutil.net_if_addrs().values():
        for a in entries:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                addrs.add(a.address.split("%")[0])
    return addrs


class BreakinGuard:
    def __init__(self, cfg, test=False, ignore_own=True):
        self.cfg = cfg
        self.test = test
        self.ignore_own = ignore_own
        self.stop_event = threading.Event()
        self.ssh_failures = collections.defaultdict(collections.deque)
        self.scan_ports = collections.defaultdict(dict)  # ip -> {port: time}
        self.handled = {}  # ip -> time we last reacted
        self.lock = threading.Lock()
        self.trusted = []
        for net in cfg["trusted_ips"]:
            try:
                self.trusted.append(ipaddress.ip_network(net, strict=False))
            except ValueError:
                log.error("Ignoring bad trusted address: %s", net)
        self.own = own_addresses()
        self.can_block = False
        self.attacks = []  # used by the self-test

    def start(self, ssh=True, scans=True):
        if self.cfg["auto_block"]:
            self.can_block = firewall.setup()
        threading.Thread(target=self._update_lists_daily, daemon=True).start()
        if ssh:
            threading.Thread(target=follow_ssh_log, args=(self.on_ssh_line, self.stop_event),
                             daemon=True).start()
        if scans:
            try:
                self.sock = open_syn_socket()
                self.sock.settimeout(1)
                threading.Thread(target=self._scan_loop, daemon=True).start()
            except OSError as e:
                log.error("Port scan detection is off: %s", e)
        log.info("Break-in guard running (blocking %s).",
                 "on" if self.can_block else "off")

    def stop(self):
        self.stop_event.set()

    def _update_lists_daily(self):
        while not self.stop_event.is_set():
            ipintel.update_lists()
            self.stop_event.wait(6 * 3600)

    def is_trusted(self, ip):
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or (self.ignore_own and ip in self.own):
            return True
        return any(addr in net for net in self.trusted)

    # --- SSH ---

    def on_ssh_line(self, line):
        found = parse_ssh_line(line)
        if not found:
            return
        ip, user = found
        if self.is_trusted(ip):
            return
        now = time.time()
        window = self.cfg["ssh_window_minutes"] * 60
        with self.lock:
            times = self.ssh_failures[ip]
            times.append(now)
            while times and times[0] < now - window:
                times.popleft()
            count = len(times)
        if count >= self.cfg["ssh_max_failures"]:
            self.react(ip, "SSH password guessing",
                       f"{count} failed logins in {self.cfg['ssh_window_minutes']} min "
                       f"(last tried user: {user})")

    # --- port scans ---

    def _scan_loop(self):
        while not self.stop_event.is_set():
            try:
                packet = self.sock.recv(256)
            except socket.timeout:
                continue
            except OSError:
                return
            found = parse_syn(packet)
            if found:
                self.on_syn(*found)

    def on_syn(self, ip, port):
        if self.is_trusted(ip):
            return
        now = time.time()
        window = self.cfg["scan_window_seconds"]
        with self.lock:
            ports = self.scan_ports[ip]
            ports[port] = now
            for p in [p for p, t in ports.items() if t < now - window]:
                del ports[p]
            count = len(ports)
            if len(self.scan_ports) > 10000:  # don't grow forever
                self.scan_ports.clear()
        if count >= self.cfg["scan_ports"]:
            self.react(ip, "Port scan",
                       f"tried {count} different ports in {window} seconds")

    # --- reaction ---

    def react(self, ip, attack, detail):
        with self.lock:
            # React once per attacker while it's blocked anyway.
            if time.time() - self.handled.get(ip, 0) < self.cfg["block_hours"] * 3600:
                return
            self.handled[ip] = time.time()
            self.ssh_failures.pop(ip, None)
            self.scan_ports.pop(ip, None)

        blocked = False
        if self.can_block:
            try:
                firewall.block(ip, self.cfg["block_hours"])
                blocked = True
            except (RuntimeError, ValueError) as e:
                log.error("Could not block %s: %s", ip, e)

        info = ipintel.lookup(ip, online=self.cfg["ip_lookup"])
        entry = {"type": "attack", "time": time.time(), "ip": ip, "attack": attack,
                 "detail": detail, "blocked": blocked,
                 "block_hours": self.cfg["block_hours"], "info": info, "test": self.test}
        self.attacks.append(entry)
        record(entry)

        where = ", ".join(p for p in (info["location"], info["isp"]) if p)
        lines = [f"{attack} from {ip}", detail]
        if where:
            lines.append(where)
        lines.append(info["label"])
        if blocked:
            lines.append(f"Blocked for {self.cfg['block_hours']} h.")
        elif not self.cfg["auto_block"]:
            lines.append("Not blocked (blocking is switched off in the settings).")
        else:
            lines.append("NOT blocked (firewall not available).")
        log.warning("BREAK-IN ATTEMPT: %s", " | ".join(lines))
        popup("🚫 Break-in attempt" + (" blocked" if blocked else ""),
              "\n".join(lines), "critical")


def record(entry):
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.ATTACKS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log.error("Could not save attack history: %s", e)


def read_attacks():
    """Attacks, newest last, with 'status' filled in (blocked/expired/unblocked)."""
    attacks, unblocked = [], {}
    try:
        with open(config.ATTACKS_FILE) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if e.get("type") == "unblock":
                    unblocked[e["ip"]] = e["time"]
                else:
                    attacks.append(e)
    except OSError:
        pass
    for a in attacks:
        until = a["time"] + a.get("block_hours", 0) * 3600
        if not a.get("blocked"):
            a["status"] = "not blocked"
        elif unblocked.get(a["ip"], 0) > a["time"]:
            a["status"] = "unblocked"
        elif until < time.time():
            a["status"] = "expired"
        else:
            a["status"] = "blocked"
        a["blocked_until"] = until
    return attacks
