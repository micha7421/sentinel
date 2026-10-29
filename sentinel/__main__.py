"""Sentinel command line.

  python -m sentinel run                 start protection (used by the service)
  python -m sentinel test-popup          show a test popup
  python -m sentinel test-ransomware     safe test with fake ransomware
  python -m sentinel quarantine          list quarantined programs
  python -m sentinel restore ID          put a quarantined program back
  python -m sentinel delete ID           delete a quarantined program for good
  python -m sentinel apply-config FILE   check and use new settings (root)
  python -m sentinel test-breakin        safe test of the break-in guard
  python -m sentinel unblock IP          unblock an IP address
  python -m sentinel lookup IP           who is behind an IP? (VPN, Tor, ...)
  python -m sentinel check-system        Gentoo: check system programs
  python -m sentinel gui                 open the Sentinel window
"""

import argparse
import json
import logging
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import breakin, config, firewall, ipintel, notify, portage_db, quarantine
from .notify import popup
from .ransomware import RansomwareGuard


def setup_logging():
    handlers = [logging.StreamHandler()]
    try:
        config.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(config.LOG_FILE))
    except OSError:
        pass  # e.g. the window, running as a normal user
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=handlers)


def cmd_run(args):
    cfg = config.load()
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    guard = RansomwareGuard(cfg)
    guard.start()
    breakin_guard = None
    if cfg["breakin_guard"]:
        breakin_guard = breakin.BreakinGuard(cfg)
        breakin_guard.start()
    if cfg["system_check"] and portage_db.available():
        threading.Thread(target=daily_system_check, args=(stop,), daemon=True).start()

    popup("Sentinel is running", "Your PC is being protected.", "low")
    stop.wait()
    guard.stop()
    if breakin_guard:
        breakin_guard.stop()
    logging.getLogger("sentinel").info("Sentinel stopped.")


def system_check(slow=False):
    """Check system programs against Portage's records, save and report."""
    result = portage_db.check_system(slow=slow)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.INTEGRITY_FILE.write_text(json.dumps(result, indent=1))
    bad = result["changed"] + result["missing"]
    if bad:
        packages = sorted({b["package"] for b in bad})
        popup("⚠️ System programs were changed!",
              f"{len(result['changed'])} changed, {len(result['missing'])} missing, "
              f"from: {', '.join(packages[:5])}\n"
              f"Fix with: emerge -1 {' '.join('=' + p for p in packages[:5])}",
              "critical")
    return result


def daily_system_check(stop):
    try:
        last = json.loads(config.INTEGRITY_FILE.read_text())["time"]
    except (OSError, ValueError, KeyError):
        last = 0
    # First check 10 minutes after boot at the earliest, then once a day.
    wait = max(600, last + 86400 - time.time())
    while not stop.wait(wait):
        system_check(slow=True)
        wait = 86400


def cmd_test_popup(args):
    popup("Sentinel test", "If you can read this, popups work! 🎉", "normal")


def cmd_test_ransomware(args):
    """Create a throwaway folder, start a guard on it, release fake
    ransomware inside and check that it gets stopped."""
    folder = config.DATA_DIR / "test-folder"
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    (folder / ".sentinel-test-folder").touch()
    for i in range(60):
        (folder / f"document-{i:02}.txt").write_text(f"My important file {i}\n" * 200)

    script = folder / ".fake_ransomware.py"
    shutil.copy(Path(__file__).parent / "fake_ransomware.py", script)

    cfg = config.load()
    cfg["canaries"] = not args.no_traps
    guard = RansomwareGuard(cfg, watch_dirs=[folder], test=True)
    guard.start()

    print("Releasing fake ransomware in", folder)
    proc = subprocess.Popen([sys.executable, str(script), str(folder)])
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
    guard.stop()

    locked = len(list(folder.glob("*.locked")))
    if proc.returncode == -signal.SIGKILL and guard.alarm_count:
        print(f"\n✅ TEST PASSED: fake ransomware was stopped after "
              f"{locked} of 60 test files.")
        ok = True
    else:
        print("\n❌ TEST FAILED: the fake ransomware was not stopped.")
        ok = False

    # Clean up the test quarantine items and the folder.
    for item in quarantine.list_items():
        if item["original"] == str(script):
            quarantine.delete(item["id"])
    shutil.rmtree(folder, ignore_errors=True)
    sys.exit(0 if ok else 1)


def cmd_quarantine(args):
    items = quarantine.list_items()
    if not items:
        print("Quarantine is empty.")
    for item in items:
        print(f"{item['id']}\n  from:   {item['original']}\n"
              f"  when:   {item['time']}\n  reason: {item['reason']}\n")


def cmd_restore(args):
    try:
        print("Restored to", quarantine.restore(args.id))
    except (ValueError, OSError) as e:
        sys.exit(f"Could not restore: {e}")


def cmd_delete(args):
    try:
        quarantine.delete(args.id)
    except (ValueError, OSError) as e:
        sys.exit(f"Could not delete: {e}")
    print("Deleted.")


def cmd_apply_config(args):
    if not config.IS_ROOT:
        sys.exit("apply-config needs root.")
    new = config.load_raw(Path(args.file))
    try:
        config.validate(new)
        if new["user"]:
            pwd.getpwnam(new["user"])
    except (ValueError, KeyError) as e:
        sys.exit(f"Settings not saved: {e}")
    config.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    config.CONFIG_FILE.write_text(config.to_toml(new))
    subprocess.run(["systemctl", "try-restart", "sentinel"], check=False)
    print("Settings saved.")


def cmd_check_system(args):
    if not portage_db.available():
        sys.exit("This only works on Gentoo (no /var/db/pkg).")
    print("Checking system programs against Portage's records...")
    r = system_check()
    print(f"Checked {r['checked']} files in {r['seconds']} s.")
    for b in r["changed"]:
        print(f"  CHANGED  {b['path']}  ({b['package']})")
    for b in r["missing"]:
        print(f"  MISSING  {b['path']}  ({b['package']})")
    if not r["changed"] and not r["missing"]:
        print("✅ Everything matches what Portage installed.")


def cmd_unblock(args):
    try:
        firewall.unblock(args.ip)
    except (RuntimeError, ValueError) as e:
        sys.exit(f"Could not unblock: {e}")
    breakin.record({"type": "unblock", "ip": args.ip, "time": time.time()})
    print(f"{args.ip} is unblocked.")


def cmd_lookup(args):
    if config.IS_ROOT:
        ipintel.update_lists()
    info = ipintel.lookup(args.ip)
    for key in ("ip", "label", "location", "isp", "network", "abuse_email"):
        if info.get(key):
            print(f"{key:12} {info[key]}")


def cmd_test_breakin(args):
    """Safe test: VPN/Tor check, a fake SSH attack from a test address, and
    a real port scan of this PC."""
    cfg = config.load()
    cfg["block_hours"] = 1
    results = []

    print("1) VPN / Tor check")
    print(f"   {ipintel.update_lists()} of {len(ipintel.LISTS)} lists downloaded")
    try:
        tor_ip = (ipintel._lists_dir() / "tor.txt").read_text().split()[0]
        info = ipintel.lookup(tor_ip, online=cfg["ip_lookup"])
        print(f"   {tor_ip} (a Tor exit node): {info['label']}")
        results.append(("Tor exit node recognized", info["kind"] == "tor"))
    except (OSError, IndexError):
        results.append(("Tor list downloaded", False))

    print("2) Fake SSH attack from 203.0.113.66 (an address reserved for tests)")
    guard = breakin.BreakinGuard(cfg, test=True)
    guard.can_block = cfg["auto_block"] and firewall.setup()
    for i in range(cfg["ssh_max_failures"]):
        guard.on_ssh_line(f"Failed password for root from 203.0.113.66 port {40000 + i} ssh2")
    results.append(("SSH attack detected", bool(guard.attacks)))
    if guard.can_block:
        listed = any(b["ip"] == "203.0.113.66" for b in firewall.blocked())
        results.append(("Attacker blocked in firewall", listed))
        firewall.unblock("203.0.113.66")
        breakin.record({"type": "unblock", "ip": "203.0.113.66", "time": time.time()})

    print("3) Port scan against this PC")
    scan_cfg = dict(cfg, auto_block=False)
    scanner = breakin.BreakinGuard(scan_cfg, test=True, ignore_own=False)
    scanner.start(ssh=False)
    time.sleep(0.5)
    own = [a for a in breakin.own_addresses()
           if "." in a and not a.startswith("127.")]
    if own:
        for port in range(20000, 20000 + cfg["scan_ports"] + 5):
            s = socket.socket()
            s.settimeout(0.3)
            try:
                s.connect((own[0], port))
            except OSError:
                pass
            s.close()
        time.sleep(1.5)
        results.append(("Port scan detected", bool(scanner.attacks)))
    else:
        print("   No network connection, skipped.")
    scanner.stop()

    print()
    for name, ok in results:
        print(("✅ " if ok else "❌ ") + name)
    sys.exit(0 if all(ok for _, ok in results) else 1)


def cmd_gui(args):
    try:
        from .gui import run_gui
    except ImportError:
        sys.exit("The window needs PyQt6. On Gentoo: emerge dev-python/pyqt6 "
                 "(or app-antivirus/sentinel with USE=gui)")
    run_gui()


def main():
    parser = argparse.ArgumentParser(prog="sentinel", description="Sentinel security guard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run", help="start protection").set_defaults(func=cmd_run)
    sub.add_parser("test-popup", help="show a test popup").set_defaults(func=cmd_test_popup)
    t = sub.add_parser("test-ransomware", help="safe test with fake ransomware")
    t.add_argument("--no-traps", action="store_true",
                   help="test detection without trap files")
    t.set_defaults(func=cmd_test_ransomware)
    sub.add_parser("quarantine", help="list quarantined programs").set_defaults(func=cmd_quarantine)
    r = sub.add_parser("restore", help="restore a quarantined program")
    r.add_argument("id")
    r.set_defaults(func=cmd_restore)
    d = sub.add_parser("delete", help="delete a quarantined program for good")
    d.add_argument("id")
    d.set_defaults(func=cmd_delete)
    a = sub.add_parser("apply-config", help="check and use new settings (root)")
    a.add_argument("file")
    a.set_defaults(func=cmd_apply_config)
    sub.add_parser("test-breakin", help="safe test of the break-in guard").set_defaults(func=cmd_test_breakin)
    u = sub.add_parser("unblock", help="unblock an IP address")
    u.add_argument("ip")
    u.set_defaults(func=cmd_unblock)
    lk = sub.add_parser("lookup", help="who is behind an IP? (VPN, Tor, ...)")
    lk.add_argument("ip")
    lk.set_defaults(func=cmd_lookup)
    sub.add_parser("check-system", help="Gentoo: check system programs").set_defaults(func=cmd_check_system)
    g = sub.add_parser("gui", help="open the Sentinel window")
    g.add_argument("--tray", action="store_true", help="start hidden in the tray")
    g.set_defaults(func=cmd_gui)

    args = parser.parse_args()
    setup_logging()
    cfg = config.load()
    notify.desktop_user = (cfg["user"], cfg["uid"])
    args.func(args)


if __name__ == "__main__":
    main()
