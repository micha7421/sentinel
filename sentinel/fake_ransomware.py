"""HARMLESS fake ransomware, used only by `sentinel test-ransomware`.

It refuses to run unless the folder contains the marker file
.sentinel-test-folder, so it can never touch your real files.
"""

import os
import sys
import time

folder = sys.argv[1]
if not os.path.exists(os.path.join(folder, ".sentinel-test-folder")):
    sys.exit("Not a Sentinel test folder, refusing to run.")

with open(os.path.join(folder, "HOW_TO_DECRYPT_YOUR_FILES.txt"), "w") as f:
    f.write("This is a fake ransom note from the Sentinel test.\n")

for name in sorted(os.listdir(folder)):
    path = os.path.join(folder, name)
    if name.startswith(".") or name.startswith("HOW_TO") or not os.path.isfile(path):
        continue
    size = os.path.getsize(path)
    with open(path, "wb") as f:
        f.write(os.urandom(max(size, 4096)))  # "encrypt" = fill with random bytes
    os.rename(path, path + ".locked")
    time.sleep(0.05)

print("Fake ransomware finished WITHOUT being stopped (the test failed).")
