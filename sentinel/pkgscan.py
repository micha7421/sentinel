"""Supply-chain guard: look inside a package BEFORE it is installed.

A pacman hook runs this on every install/upgrade. It opens each incoming
package and looks for the tricks a poisoned package would use:

  - an install script that downloads and runs code, edits sudoers, adds a
    SUID bit, writes to /etc/ld.so.preload, opens a reverse shell, ...
  - SUID/SGID programs (they run as root)
  - files dropped into sensitive places (sudoers.d, cron, PAM, autostart,
    profile.d, ld.so.preload)

By default it only WARNS (never blocks your updates). Set package_scan_block
in the config to stop an install when something high-risk is found.
"""

import logging
import re
import shutil
import subprocess
from pathlib import Path

log = logging.getLogger("sentinel")

HIGH, MEDIUM, INFO = "HIGH", "MEDIUM", "INFO"
CACHE = "/var/cache/pacman/pkg"

# Risky things an install script might do. (pattern, level, explanation)
SCRIPT_RULES = [
    (r"(?:curl|wget|fetch)[^\n|&]*\|\s*(?:ba)?sh", HIGH, "downloads and runs code"),
    (r"(?:curl|wget)\s+[^\n]*\b(?:\d{1,3}\.){3}\d{1,3}", HIGH, "downloads from a bare IP address"),
    (r"/dev/tcp/|\bncat?\b\s+-[a-z]*e|\bnc\b\s+[^\n]*-[a-z]*e", HIGH, "opens a reverse shell"),
    (r"/etc/ld\.so\.preload", HIGH, "edits /etc/ld.so.preload (hijacks every program)"),
    (r"/etc/sudoers", HIGH, "edits sudoers (grants root)"),
    (r"chmod\s+[0-7]*[4-7][0-7]{3}\b|chmod\s+[ugoa]*\+s", HIGH, "adds a SUID bit"),
    (r">>?\s*/etc/passwd|\buseradd\b|\busermod\b[^\n]*(?:wheel|sudo|root)", HIGH, "creates or elevates a user"),
    (r"base64\s+-{1,2}d|\beval\b|\\x[0-9a-fA-F]{2}", MEDIUM, "runs obfuscated code"),
    (r"crontab|/etc/cron", MEDIUM, "adds a cron job"),
    (r"autostart|/etc/profile\.d|\.bashrc|\.zshrc", MEDIUM, "adds itself to autostart/login"),
    (r"/etc/pam\.d|pam_", MEDIUM, "changes how logins are checked (PAM)"),
    (r"\bsystemctl\s+enable\b|\.service\b", INFO, "enables a system service (common, but check it)"),
]

# Files landing in sensitive locations. (path-prefix test, level, explanation)
SENSITIVE_PATHS = [
    ("etc/ld.so.preload", HIGH, "replaces /etc/ld.so.preload"),
    ("etc/sudoers", HIGH, "drops a sudoers rule"),
    ("etc/cron", MEDIUM, "installs a cron job"),
    ("etc/pam.d/", MEDIUM, "installs a PAM rule"),
    ("etc/profile.d/", MEDIUM, "runs code at every login"),
    ("etc/xdg/autostart/", MEDIUM, "adds a desktop autostart entry"),
    ("etc/polkit-1/", MEDIUM, "changes who may do privileged actions"),
]


def _tar_cmd():
    return "bsdtar" if shutil.which("bsdtar") else "tar"


def _run(args):
    return subprocess.run([_tar_cmd(), *args], capture_output=True, text=True)


def list_entries(pkg):
    """[(perms, path)] for every entry, using a verbose listing."""
    r = _run(["-tvf", str(pkg)])
    if r.returncode != 0:  # GNU tar may need the explicit flag for zstd
        r = _run(["--zstd", "-tvf", str(pkg)])
    entries = []
    for line in r.stdout.splitlines():
        parts = line.split(None, 5)
        if len(parts) >= 6 and parts[0][:1] in "-dlpbc":
            entries.append((parts[0], parts[-1].lstrip("./")))
    return entries


def scriptlet(pkg):
    """The package's .INSTALL script (post_install/upgrade hooks), or ''."""
    for extra in ([], ["--zstd"]):
        r = _run([*extra, "-xOf", str(pkg), ".INSTALL"])
        if r.returncode == 0:
            return r.stdout
    return ""


def is_setuid(perms):
    # perms like -rwsr-xr-x : 's'/'S' in the owner (3) or group (6) exec slot.
    return len(perms) >= 7 and (perms[3] in "sS" or perms[6] in "sS")


def scan_file(pkg):
    """Return a list of findings for one package file."""
    pkg = Path(pkg)
    findings = []
    name = pkg.name.split("-")[0]

    script = scriptlet(pkg)
    for pattern, level, why in SCRIPT_RULES:
        if re.search(pattern, script, re.IGNORECASE):
            findings.append((level, f"install script {why}"))

    for perms, path in list_entries(pkg):
        if perms[:1] == "d":   # directories themselves aren't a finding
            continue
        if path in (".INSTALL", ".PKGINFO", ".MTREE", ".BUILDINFO", ""):
            continue
        if is_setuid(perms):
            # SUID in the usual places is common (sudo, ping); elsewhere it's
            # more suspicious.
            usual = path.startswith(("usr/bin/", "usr/lib/", "bin/", "usr/sbin/"))
            findings.append((MEDIUM if usual else HIGH, f"SUID/SGID program: /{path}"))
        for prefix, level, why in SENSITIVE_PATHS:
            if path.startswith(prefix):
                findings.append((level, f"{why}: /{path}"))

    # De-duplicate, keep the highest level per message.
    order = {HIGH: 0, MEDIUM: 1, INFO: 2}
    best = {}
    for level, msg in findings:
        if msg not in best or order[level] < order[best[msg]]:
            best[msg] = level
    return name, [(lvl, msg) for msg, lvl in best.items()]


def resolve_from_cache(names):
    """Map pacman target names to the newest matching file in the cache."""
    cache = Path(CACHE)
    files = []
    for target in names:
        name = target.strip().split("/")[-1]  # drop any repo/ prefix
        if not name:
            continue
        matches = sorted(cache.glob(f"{name}-*.pkg.tar.*"),
                         key=lambda p: p.stat().st_mtime, reverse=True)
        matches = [m for m in matches if not m.name.endswith(".sig")]
        if matches:
            files.append(matches[0])
        else:
            log.info("Package scan: no cached file for %s", name)
    return files
