import gzip
import hashlib
import pytest
from sentinel import pacman_db


def sha(b):
    return hashlib.sha256(b).hexdigest()


@pytest.fixture
def fake_db(tmp_path, monkeypatch):
    local = tmp_path / "local"
    local.mkdir()
    monkeypatch.setattr(pacman_db, "LOCAL", local)
    # No pacman binary in the test env -> owner() falls back to the files list.
    monkeypatch.setattr(pacman_db.shutil, "which", lambda *a: None)

    realfile = tmp_path / "bin_true"
    realfile.write_bytes(b"ELF-ish\n")
    good = sha(realfile.read_bytes())

    pkg = local / "coreutils-9.5-1"
    pkg.mkdir()
    (pkg / "files").write_text("%FILES%\n" + f"{str(realfile).lstrip('/')}\n"
                               "usr/bin/this is missing\n")
    mtree = ("#mtree\n/set type=file\n"
             f".{realfile} size=8 sha256digest={good} mode=0755\n"
             f"./usr/bin/this\\040is\\040missing size=1 sha256digest={'1'*64} mode=0755\n")
    with gzip.open(pkg / "mtree", "wb") as f:
        f.write(mtree.encode())
    return {"local": local, "realfile": realfile, "good": good}


def test_available(fake_db):
    assert pacman_db.available()


def test_unvis():
    assert pacman_db._unvis(b"this\\040is\\040missing") == "this is missing"
    assert pacman_db._unvis(b"plain") == "plain"


def test_pkg_name():
    from pathlib import Path
    assert pacman_db._pkg_name(Path("/x/coreutils-9.5-1")) == "coreutils"
    assert pacman_db._pkg_name(Path("/x/gtk3-1:3.24-2")) == "gtk3"


def test_owner_found_and_missing(fake_db):
    assert pacman_db.owner(str(fake_db["realfile"])) == ("coreutils", None)
    assert pacman_db.owner("/tmp/definitely-not-owned") is None


def test_is_genuine(fake_db):
    pkg, ok = pacman_db.is_genuine(str(fake_db["realfile"]))
    assert pkg == "coreutils" and ok is True
    fake_db["realfile"].write_bytes(b"TAMPERED")
    pkg, ok = pacman_db.is_genuine(str(fake_db["realfile"]))
    assert ok is False


def test_check_system(fake_db):
    # Only system-dir paths are checked; point the check at the real file.
    r = pacman_db.check_system(prefixes=(str(fake_db["realfile"]), "/usr/bin/"))
    changed = [c["path"] for c in r["changed"]]
    missing = [m["path"] for m in r["missing"]]
    assert "/usr/bin/this is missing" in missing
    assert str(fake_db["realfile"]) not in changed  # matches, so not flagged
