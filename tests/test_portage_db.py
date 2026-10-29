import hashlib
import pytest
from sentinel import portage_db


def md5(b):
    return hashlib.md5(b).hexdigest()


@pytest.fixture
def fake_vdb(tmp_path, monkeypatch):
    vdb = tmp_path / "pkg"
    vdb.mkdir()
    monkeypatch.setattr(portage_db, "VDB", vdb)

    realfile = tmp_path / "ls"
    realfile.write_bytes(b"binary\n")
    good = md5(realfile.read_bytes())

    pkgdir = vdb / "sys-apps" / "coreutils-9.5"
    pkgdir.mkdir(parents=True)
    (pkgdir / "CONTENTS").write_text(
        f"dir /usr/bin\n"
        f"obj {realfile} {good} 1700000000\n"
        f"obj /usr/bin/with space {'0'*32} 1700000000\n"
        f"sym /usr/bin/foo -> ls 1700000000\n")
    return {"vdb": vdb, "realfile": realfile}


def test_available(fake_vdb):
    assert portage_db.available()


def test_name_variants():
    v = portage_db._name_variants("/usr/bin/bash")
    assert "/bin/bash" in v and "/usr/bin/bash" in v


def test_parse_obj_with_spaces():
    path, m = portage_db._parse_obj("obj /usr/bin/with space abc123 1700000000")
    assert path == "/usr/bin/with space" and m == "abc123"


def test_owner(fake_vdb):
    assert portage_db.owner(str(fake_vdb["realfile"]))[0] == "sys-apps/coreutils-9.5"
    assert portage_db.owner("/tmp/not-owned") is None


def test_is_genuine(fake_vdb):
    pkg, ok = portage_db.is_genuine(str(fake_vdb["realfile"]))
    assert pkg == "sys-apps/coreutils-9.5" and ok is True
    fake_vdb["realfile"].write_bytes(b"changed!")
    _, ok = portage_db.is_genuine(str(fake_vdb["realfile"]))
    assert ok is False


def test_check_system_missing(fake_vdb):
    r = portage_db.check_system(prefixes=("/usr/bin/",))
    missing = [m["path"] for m in r["missing"]]
    assert "/usr/bin/with space" in missing


def test_repair_command():
    assert portage_db.repair_command(["a/b", "c/d"]) == "emerge -1 =a/b =c/d"
