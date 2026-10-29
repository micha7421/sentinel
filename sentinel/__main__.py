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
  python -m sentinel check-system        check system programs vs package manager
  python -m sentinel scan-package FILE   scan a package for supply-chain risks
  python -m sentinel test-threats        safe test of credential/persistence/crash guards
  python -m sentinel gui                 open the Sentinel window
"""

import argparse
import json
import logging
import os
import pwd
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import (breakin, config, firewall, ipintel, notify, packages,
               quarantine)
from .credential import CredentialGuard
from .crash import CrashGuard
from .notify import popup
from .persistence import PersistenceGuard
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

    guards = [RansomwareGuard(cfg)]
    if cfg["breakin_guard"]:
        guards.append(breakin.BreakinGuard(cfg))
    if cfg["credential_guard"]:
        guards.append(CredentialGuard(cfg))
    if cfg["persistence_guard"]:
        guards.append(PersistenceGuard(cfg))
    if cfg["crash_guard"]:
        guards.append(CrashGuard(cfg))
    for g in guards:
        g.start()
    if cfg["system_check"] and packages.available():
        threading.Thread(target=daily_system_check, args=(stop,), daemon=True).start()

    popup("Sentinel is running", "Your PC is being protected.", "low")
    stop.wait()
    for g in guards:
        g.stop()
    logging.getLogger("sentinel").info("Sentinel stopped.")


def system_check(slow=False):
    """Check system programs against Portage's records, save and report."""
    result = packages.check_system(slow=slow)
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.INTEGRITY_FILE.write_text(json.dumps(result, indent=1))
    bad = result["changed"] + result["missing"]
    if bad:
        pkgs = sorted({b["package"] for b in bad})
        popup("⚠️ System programs were changed!",
              f"{len(result['changed'])} changed, {len(result['missing'])} missing, "
              f"from: {', '.join(pkgs[:5])}\n"
              f"Fix with: {packages.repair_command(pkgs[:5])}",
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
    if not packages.available():
        sys.exit("No supported package manager found (Portage or pacman).")
    print(f"Checking system programs against {packages.name()}'s records...")
    r = system_check()
    print(f"Checked {r['checked']} files in {r['seconds']} s.")
    for b in r["changed"]:
        print(f"  CHANGED  {b['path']}  ({b['package']})")
    for b in r["missing"]:
        print(f"  MISSING  {b['path']}  ({b['package']})")
    if not r["changed"] and not r["missing"]:
        print(f"✅ Everything matches what {packages.name()} installed.")


LEVEL_MARK = {"HIGH": "🔴", "MEDIUM": "🟡", "INFO": "🔵"}


def cmd_scan_package(args):
    """Wrapper that FAILS OPEN: a bug in the scanner must never block pacman.
    Only a deliberate 'blocked' decision exits non-zero."""
    try:
        _scan_package(args)
    except SystemExit:
        raise  # deliberate block/allow decision
    except Exception as e:
        logging.getLogger("sentinel").error("Package scan error (ignored): %s", e)
        print(f"Sentinel: package scan skipped ({e}).")
        sys.exit(0)


def _scan_package(args):
    """Scan package files for supply-chain risks. With no files, read pacman
    target names from stdin (this is how the pacman hook calls us)."""
    from . import pkgscan
    cfg = config.load_raw()
    if args.files:
        pkgs = [Path(f) for f in args.files]
    elif not sys.stdin.isatty():
        pkgs = pkgscan.resolve_from_cache(sys.stdin.read().splitlines())
    else:
        sys.exit("Give package files to scan, or pipe pacman target names in.")

    worst = None
    order = {"HIGH": 0, "MEDIUM": 1, "INFO": 2}
    for pkg in pkgs:
        try:
            name, findings = pkgscan.scan_file(pkg)
        except OSError as e:
            print(f"Sentinel: could not scan {pkg}: {e}")
            continue
        if not findings:
            continue
        findings.sort(key=lambda f: order[f[0]])
        print(f"\nSentinel — risky things in package '{name}':")
        for level, msg in findings:
            print(f"  {LEVEL_MARK[level]} {level}: {msg}")
        top = findings[0][0]
        if worst is None or order[top] < order[worst]:
            worst = top

    if worst == "HIGH":
        popup("⚠️ Risky package being installed",
              "A package pacman is installing does something dangerous "
              "(see the terminal). Only continue if you trust it.", "critical")
        if cfg["package_scan_block"]:
            print("\nSentinel BLOCKED this install (package_scan_block is on). "
                  "Install by hand if you are sure it is safe.")
            sys.exit(1)
    if worst:
        print("\nSentinel: this is a warning, not proof of malware. Check the "
              "package if anything looks wrong.")
    sys.exit(0)


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


def cmd_test_threats(args):
    """Safe test of the credential, persistence and crash guards, all inside a
    throwaway folder. Nothing real is read, moved or harmed."""
    folder = config.DATA_DIR / "threat-test"
    shutil.rmtree(folder, ignore_errors=True)
    (folder / "home/.ssh").mkdir(parents=True)
    (folder / "home/Documents").mkdir(parents=True)
    (folder / ".sentinel-test-folder").touch()
    home = folder / "home"
    # Stand-ins for the real secrets, so we never touch the real ones.
    fake_shadow = folder / "shadow"
    fake_shadow.write_text("root:$6$fakehash:19000:0:99999:7:::\n")
    (home / ".ssh/id_rsa").write_text("FAKE TEST KEY, not a real one\n")

    cfg = config.load()
    cfg["home"] = str(home)
    results = []
    # The guard quarantines the script a "thief" runs, so give every probe run
    # its OWN fresh copy inside the test folder (the packaged source stays put).
    source_probe = Path(__file__).parent / "threat_probe.py"
    counter = [0]

    def fresh_probe():
        counter[0] += 1
        copy = folder / f".probe{counter[0]}.py"
        shutil.copy(source_probe, copy)
        return copy

    def run_probe(interpreter, *paths):
        probe = fresh_probe()
        p = subprocess.Popen([interpreter, str(probe), str(folder), *map(str, paths)])
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
        return p

    print("1) Credential guard: a test program reads fake secrets and bait")
    cred = CredentialGuard(cfg, home=home, test=True,
                           watch={str(fake_shadow): set(),
                                  str(home / ".ssh/id_rsa"): {"ssh", "sshd"}})
    if cred.start():
        time.sleep(0.3)
        bait = next(iter(cred.bait), None)
        run_probe(sys.executable, fake_shadow, home / ".ssh/id_rsa",
                  *([bait] if bait else []))
        time.sleep(0.5)
        cred.stop()
        results.append(("Reading /etc/shadow-style file is detected", cred.alarm_count >= 1))
        results.append(("Reading a decoy password file is detected", bait is not None
                        and cred.alarm_count >= 2))

        # Evasion: a program that renames itself to a trusted name ("baloo_file")
        # but runs from the wrong place must still be caught.
        if bait:
            cred2 = CredentialGuard(cfg, home=home, test=True, watch={})
            if cred2.start():
                time.sleep(0.3)
                disguised = folder / "baloo_file"      # a trusted name...
                shutil.copy(sys.executable, disguised)  # ...but in the test folder
                run_probe(str(disguised), bait)         # fresh probe copy
                time.sleep(0.5)
                cred2.stop()
                results.append(("A thief disguised as 'baloo_file' is still caught",
                                cred2.alarm_count >= 1))

        for item in quarantine.list_items():  # clean up anything quarantined
            if str(folder) in item["original"] or "threat_probe" in item["original"]:
                quarantine.delete(item["id"])
    else:
        print("   (needs root; skipped)")

    print("2) Persistence guard: a test entry is dropped into autostart")
    pers = PersistenceGuard(cfg, home=home, test=True)
    pers.start()
    time.sleep(0.3)
    (home / ".config/autostart").mkdir(parents=True, exist_ok=True)
    (home / ".config/autostart/evil.desktop").write_text(
        "[Desktop Entry]\nType=Application\nExec=/tmp/whatever\n")
    with open(home / ".bashrc", "a") as f:
        f.write("\n# added by a test\n/tmp/whatever &\n")
    time.sleep(1.0)
    pers.stop()
    results.append(("New autostart entry is detected", pers.alarm_count >= 1))

    print("3) Crash guard: a small, capped burst of processes")
    crashg = CrashGuard(cfg, test=True)
    crashg.limit = 15
    crashg.start()
    # Spawn the burst under its OWN session leader, so freezing that family
    # can never reach this test process.
    burst = subprocess.Popen(
        ["sh", "-c", "for i in $(seq 1 20); do sleep 20 & done; wait"],
        start_new_session=True)
    time.sleep(2.5)
    crashg.stop()
    try:  # unfreeze and clean up the whole burst group
        os.killpg(burst.pid, signal.SIGCONT)
        os.killpg(burst.pid, signal.SIGKILL)
    except OSError:
        pass
    burst.kill()
    results.append(("Fork bomb (process explosion) is detected", crashg.alarm_count >= 1))

    shutil.rmtree(folder, ignore_errors=True)
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
    sub.add_parser("test-threats", help="safe test of the credential/persistence/crash guards").set_defaults(func=cmd_test_threats)
    sp = sub.add_parser("scan-package", help="scan package files for supply-chain risks")
    sp.add_argument("files", nargs="*", help="package files (.pkg.tar.*); none = read names from stdin")
    sp.set_defaults(func=cmd_scan_package)
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
