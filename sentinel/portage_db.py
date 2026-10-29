"""Gentoo's package database (/var/db/pkg).

Portage writes down every file each package installed, with its MD5
checksum. Sentinel uses that to:
  - never quarantine a genuine system program
  - notice when a system program was secretly changed (e.g. by a rootkit)

On other distributions /var/db/pkg doesn't exist and this is skipped.
"""

import hashlib
import logging
import os
import time
from pathlib import Path

log = logging.getLogger("sentinel")

VDB = Path("/var/db/pkg")

# What the system check looks at: programs and the libraries that decide
# who may log in (PAM). Not /etc: config files are meant to be changed.
CHECK_PREFIXES = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
                  "/usr/libexec/", "/lib64/security/", "/usr/lib64/security/",
                  "/lib/security/", "/usr/lib/security/")


def available():
    return VDB.is_dir()


def _contents_files():
    return VDB.glob("*/*/CONTENTS")


def _package_name(contents_file):
    return f"{contents_file.parent.parent.name}/{contents_file.parent.name}"


def _parse_obj(line):
    """'obj /usr/bin/foo bar <md5> <mtime>' -> ('/usr/bin/foo bar', md5).
    Paths can contain spaces, so split from the right."""
    path, md5, _mtime = line[4:].rsplit(" ", 2)
    return path, md5


def _name_variants(path):
    """/bin/bash and /usr/bin/bash can be the same file ("merged /usr"),
    but Portage writes down only one of the names."""
    names = {path, os.path.realpath(path)}
    for p in list(names):
        if p.startswith("/usr/"):
            names.add(p[4:])
        elif p.startswith(("/bin/", "/sbin/", "/lib")):
            names.add("/usr" + p)
    return names


def owner(path):
    """Which package installed this file? Returns (package, md5) or None."""
    if not available():
        return None
    needles = [f"obj {p} ".encode() for p in _name_variants(path)]
    for contents in _contents_files():
        try:
            data = contents.read_bytes()
        except OSError:
            continue
        for needle in needles:
            start = data.find(needle)
            # Must be the start of a line, not the end of a longer path.
            while start > 0 and data[start - 1:start] != b"\n":
                start = data.find(needle, start + 1)
            if start < 0:
                continue
            end = data.find(b"\n", start)
            line = data[start:end if end >= 0 else None].decode(errors="replace")
            return _package_name(contents), _parse_obj(line)[1]
    return None


def md5_of(path):
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_genuine(path):
    """(package, True/False) if a package owns the file, else None.
    False means the file no longer matches what Portage installed."""
    found = owner(path)
    if not found:
        return None
    pkg, md5 = found
    try:
        return pkg, md5_of(path) == md5
    except OSError:
        return pkg, False


def check_system(prefixes=CHECK_PREFIXES, slow=False):
    """Compare installed programs with Portage's records.

    Returns a dict with 'changed' and 'missing' lists of
    {"path", "package"}. With slow=True it pauses now and then so it
    doesn't slow down the PC while running in the background.
    """
    changed, missing, checked = [], [], 0
    started = time.time()
    for contents in sorted(_contents_files()):
        pkg = _package_name(contents)
        try:
            lines = contents.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for line in lines:
            if not line.startswith("obj "):
                continue
            path, md5 = _parse_obj(line)
            if not path.startswith(prefixes):
                continue
            checked += 1
            try:
                if md5_of(path) != md5:
                    changed.append({"path": path, "package": pkg})
            except FileNotFoundError:
                missing.append({"path": path, "package": pkg})
            except OSError:
                pass
            if slow and checked % 200 == 0:
                time.sleep(0.2)
    return {"time": time.time(), "seconds": round(time.time() - started, 1),
            "checked": checked, "changed": changed, "missing": missing}
