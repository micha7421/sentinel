"""HARMLESS test probe, used only by `sentinel test-threats`.

It opens the files it is given, reads a few bytes and THROWS THEM AWAY. It
steals nothing, sends nothing, keeps nothing. Its only job is to make the
same file-open that a real thief would, so we can check Sentinel notices.

It refuses to run unless the first argument is a folder containing the
marker .sentinel-test-folder, so it can never be pointed at real secrets.
"""

import os
import sys
import time

marker_dir = sys.argv[1]
if not os.path.exists(os.path.join(marker_dir, ".sentinel-test-folder")):
    sys.exit("Not a Sentinel test folder, refusing to run.")

for path in sys.argv[2:]:
    try:
        with open(path, "rb") as f:
            f.read(16)   # read a little, then discard it
    except OSError:
        pass
    time.sleep(0.05)

# Stay alive briefly so the guard can see and stop us if it wants to.
time.sleep(3)
print("probe finished (not stopped)")
