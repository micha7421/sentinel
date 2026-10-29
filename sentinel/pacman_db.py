"""Arch/pacman package database (/var/lib/pacman/local).

The pacman equivalent of portage_db: it lets Sentinel know which files belong
to an installed package (so they are never quarantined) and check installed
programs against the SHA-256 hashes pacman recorded (to spot tampering).

Each installed package has a folder under /var/lib/pacman/local/<name>-<ver>/
with:
  - `files`  : the list of paths the package owns
  - `mtree`  : a gzipped list with a sha256digest for every file

On non-Arch systems /var/lib/pacman/local doesn't exist and this is skipped.
"""

import gzip
import hashlib
import logging
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

log = logging.getLogger("sentinel")

LOCAL = Path("/var/lib/pacman/local")

# Same focus as the Portage check: programs and the libraries that decide who
# may log in. Not /etc (config files are meant to be edited).
CHECK_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/security/",
                  "/usr/lib64/security/", "/bin/", "/sbin/")

_OCTAL = re.compile(rb"\\(\d{3})")


def available():
    return LOCAL.is_dir()


def _unvis(token):
    """Decode mtree's backslash escapes (e.g. '\\040' -> space)."""
    token = _OCTAL.sub(lambda m: bytes([int(m.group(1), 8)]), token)
    return token.replace(b"\\\\", b"\\").decode("utf-8", "replace")


def _mtree_files(pkg_dir):
    """Yield (absolute_path, sha256_hex) for every real file in a package."""
    mtree = pkg_dir / "mtree"
    try:
        raw = gzip.open(mtree, "rb")
    except OSError:
        return
    with raw:
        for line in raw:
            line = line.strip()
            if not line.startswith(b"./"):
                continue
            parts = line.split()
            fields = dict(p.split(b"=", 1) for p in parts[1:] if b"=" in p)
            digest = fields.get(b"sha256digest")
            if not digest:  # directories and symlinks have none
                continue
            path = "/" + _unvis(parts[0][2:])
            yield path, digest.decode()


def _pkg_name(pkg_dir):
    # Folder is "<name>-<pkgver>-<pkgrel>"; drop the last two dash fields.
    return pkg_dir.name.rsplit("-", 2)[0]


def _owns(pkg_dir, rel):
    """Does this package's `files` list contain the relative path?"""
    files = pkg_dir / "files"
    try:
        data = files.read_bytes()
    except OSError:
        return False
    return (b"\n" + rel.encode() + b"\n") in data


def owner(path):
    """Which package owns this file? Returns (package, None) or None.
    Uses `pacman -Qo` when available (fast), else scans the local database."""
    real = os.path.realpath(path)
    if shutil.which("pacman"):
        r = subprocess.run(["pacman", "-Qoq", "--", real],
                           capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip().splitlines()[0], None
        return None
    rel = real.lstrip("/")
    for pkg_dir in LOCAL.iterdir():
        if pkg_dir.is_dir() and _owns(pkg_dir, rel):
            return _pkg_name(pkg_dir), None
    return None


def md5_of(path):  # name kept for symmetry with portage_db; it's sha256 here
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_genuine(path):
    """(package, True/False) if a package owns the file, else None.
    False means the file no longer matches what pacman installed."""
    found = owner(path)
    if not found:
        return None
    pkg = found[0]
    real = os.path.realpath(path)
    for pkg_dir in LOCAL.glob(f"{pkg}-*"):
        for fpath, digest in _mtree_files(pkg_dir):
            if fpath == real:
                try:
                    return pkg, md5_of(real) == digest
                except OSError:
                    return pkg, False
    return pkg, True  # owned but not in mtree (rare): don't cry wolf


def check_system(prefixes=CHECK_PREFIXES, slow=False):
    """Compare installed programs with pacman's recorded hashes."""
    changed, missing, checked = [], [], 0
    started = time.time()
    for pkg_dir in sorted(LOCAL.iterdir()):
        if not pkg_dir.is_dir():
            continue
        pkg = _pkg_name(pkg_dir)
        for path, digest in _mtree_files(pkg_dir):
            if not path.startswith(prefixes):
                continue
            checked += 1
            try:
                if md5_of(path) != digest:
                    changed.append({"path": path, "package": pkg})
            except FileNotFoundError:
                missing.append({"path": path, "package": pkg})
            except OSError:
                pass
            if slow and checked % 200 == 0:
                time.sleep(0.2)
    return {"time": time.time(), "seconds": round(time.time() - started, 1),
            "checked": checked, "changed": changed, "missing": missing}


def repair_command(packages):
    return "pacman -S " + " ".join(packages)
