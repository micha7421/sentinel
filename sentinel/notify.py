"""Desktop popups (KDE/any freedesktop desktop) plus a log file."""

import logging
import os
import shutil
import subprocess

log = logging.getLogger("sentinel")

# Urgency: "low", "normal" or "critical". Critical popups stay until clicked.
ICONS = {
    "low": "security-high",
    "normal": "security-medium",
    "critical": "security-low",
}


# Set by the main program: (user name, uid) of the desktop user.
# Needed because a root service has no desktop of its own.
desktop_user = None


def as_desktop_user(cmd):
    if os.geteuid() != 0 or desktop_user is None:
        return cmd
    name, uid = desktop_user
    return ["runuser", "-u", name, "--", "env",
            f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"] + cmd


def popup(title, message, urgency="normal"):
    """Show a desktop popup. Always also writes to the log."""
    log.warning("%s: %s", title, message)
    icon = ICONS.get(urgency, "dialog-warning")

    if shutil.which("notify-send"):
        cmd = ["notify-send", "-a", "Sentinel", "-u", urgency, "-i", icon,
               title, message]
    elif shutil.which("gdbus"):
        # Talk to the notification service directly over D-Bus.
        level = {"low": 0, "normal": 1, "critical": 2}.get(urgency, 1)
        cmd = ["gdbus", "call", "--session",
               "--dest", "org.freedesktop.Notifications",
               "--object-path", "/org/freedesktop/Notifications",
               "--method", "org.freedesktop.Notifications.Notify",
               "Sentinel", "0", icon, title, message, "[]",
               "{'urgency': <byte %d>}" % level, "-1"]
    else:
        log.error("No popup tool found. Install x11-libs/libnotify.")
        return

    try:
        subprocess.run(as_desktop_user(cmd), check=False, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        log.error("Popup failed: %s", e)
