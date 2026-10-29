"""Quarantine: move a bad program somewhere it can't run, but can be restored."""

import json
import os
import shutil
import time
from pathlib import Path

from . import portage_db
from .config import QUARANTINE_DIR

# Never quarantine files from these places: they belong to the system
# (for example /usr/bin/python3 when the ransomware is a Python script).
SYSTEM_PREFIXES = ("/usr/", "/bin/", "/sbin/", "/lib", "/opt/", "/etc/",
                   "/boot/", "/proc/", "/sys/")


def is_system_file(path):
    return str(path).startswith(SYSTEM_PREFIXES)


def files_to_quarantine(exe, cmdline):
    """The program file itself, or the script it runs if the program is
    a system interpreter like python or bash. Never files that a Gentoo
    package installed."""
    found = []
    if exe and not is_system_file(exe) and os.path.isfile(exe):
        found.append(exe)
    for arg in cmdline[1:]:
        if os.path.isfile(arg) and not is_system_file(os.path.abspath(arg)):
            found.append(os.path.abspath(arg))
    found = [f for f in dict.fromkeys(found) if not portage_db.owner(f)]
    return found


def quarantine(path, reason):
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    item_id = time.strftime("%Y%m%d-%H%M%S") + "-" + Path(path).name
    target = QUARANTINE_DIR / item_id
    shutil.move(path, target)
    os.chmod(target, 0o400)  # read-only, not executable
    meta = {"original": path, "reason": reason, "time": time.ctime()}
    (QUARANTINE_DIR / (item_id + ".json")).write_text(json.dumps(meta, indent=2))
    return item_id


def list_items():
    if not QUARANTINE_DIR.exists():
        return []
    items = []
    for meta_file in sorted(QUARANTINE_DIR.glob("*.json")):
        meta = json.loads(meta_file.read_text())
        meta["id"] = meta_file.stem
        items.append(meta)
    return items


def _check_id(item_id):
    """Only allow plain names of real quarantine items (no ../ tricks)."""
    if "/" in item_id or item_id.startswith(".") or \
            not (QUARANTINE_DIR / (item_id + ".json")).is_file():
        raise ValueError(f"No quarantine item called {item_id!r}")


def restore(item_id):
    _check_id(item_id)
    meta_file = QUARANTINE_DIR / (item_id + ".json")
    meta = json.loads(meta_file.read_text())
    original = Path(meta["original"])
    if original.exists():
        raise FileExistsError(f"{original} already exists")
    original.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(QUARANTINE_DIR / item_id, original)
    os.chmod(original, 0o700)
    meta_file.unlink()
    return original


def delete(item_id):
    _check_id(item_id)
    (QUARANTINE_DIR / item_id).unlink(missing_ok=True)
    (QUARANTINE_DIR / (item_id + ".json")).unlink(missing_ok=True)
