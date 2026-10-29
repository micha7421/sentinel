"""One place to record a local threat (ransomware, credential theft, ...).

Everything is written to the same history file, so the window shows all of
them together on the Activity page and the tray shield turns red.
"""

import json
import logging
import time

from . import config

log = logging.getLogger("sentinel")


def record_alarm(reason, actions, kind="threat", test=False):
    entry = {"time": time.time(), "reason": reason, "actions": actions,
             "kind": kind, "test": test}
    try:
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(config.EVENTS_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError as e:
        log.error("Could not save alarm history: %s", e)
    return entry
