"""Sentinel command line.

  python -m sentinel run                 start protection (used by the service)
  python -m sentinel test-popup          show a test popup
  python -m sentinel test-ransomware     safe test with fake ransomware
  python -m sentinel quarantine          list quarantined programs
  python -m sentinel restore ID          put a quarantined program back
  python -m sentinel delete ID           delete a quarantined program for good
  python -m sentinel apply-config FILE   check and use new settings (root)
  python -m sentinel gui                 open the Sentinel window
"""

import argparse
import logging
import pwd
import shutil
import signal
import subprocess
import sys
import threading
from pathlib import Path

from . import config, notify, quarantine
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
    guard = RansomwareGuard(cfg)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    guard.start()
    popup("Sentinel is running", "Your files are being protected.", "low")
    stop.wait()
    guard.stop()
    logging.getLogger("sentinel").info("Sentinel stopped.")


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


def cmd_gui(args):
    from .gui import run_gui
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
