"""Package database, whichever this distro uses.

Sentinel works the same on Gentoo (Portage) and Arch-based distros like
Tessera (pacman): it can tell which files belong to a real package and check
installed programs against the hashes the package manager recorded. Other
systems simply have no backend and these features are skipped.
"""

from . import pacman_db, portage_db

BACKENDS = [portage_db, pacman_db]


def backend():
    for b in BACKENDS:
        if b.available():
            return b
    return None


def name():
    b = backend()
    return {"portage_db": "Portage", "pacman_db": "pacman"}.get(
        b.__name__.rsplit(".", 1)[-1], "") if b else ""


def available():
    return backend() is not None


def owner(path):
    b = backend()
    return b.owner(path) if b else None


def is_genuine(path):
    b = backend()
    return b.is_genuine(path) if b else None


def check_system(slow=False):
    b = backend()
    return b.check_system(slow=slow) if b else {
        "time": 0, "seconds": 0, "checked": 0, "changed": [], "missing": []}


def repair_command(packages):
    b = backend()
    return b.repair_command(packages) if b else ""
