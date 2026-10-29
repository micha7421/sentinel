import pytest
from sentinel import quarantine


@pytest.fixture
def qdir(tmp_path, monkeypatch):
    d = tmp_path / "quarantine"
    monkeypatch.setattr(quarantine, "QUARANTINE_DIR", d)
    return d


def test_roundtrip(qdir, tmp_path):
    victim = tmp_path / "evil.sh"
    victim.write_text("rm -rf /\n")
    item = quarantine.quarantine(str(victim), "bad")
    assert not victim.exists()
    assert len(quarantine.list_items()) == 1
    restored = quarantine.restore(item)
    assert restored.exists()
    assert quarantine.list_items() == []


def test_delete(qdir, tmp_path):
    victim = tmp_path / "x"
    victim.write_text("x")
    item = quarantine.quarantine(str(victim), "bad")
    quarantine.delete(item)
    assert quarantine.list_items() == []


@pytest.mark.parametrize("bad", ["../etc/passwd", "../../x", ".hidden", "no-such-item"])
def test_check_id_rejects(qdir, bad):
    qdir.mkdir(parents=True, exist_ok=True)
    with pytest.raises(ValueError):
        quarantine.restore(bad)
    with pytest.raises(ValueError):
        quarantine.delete(bad)


def test_files_to_quarantine_filters(monkeypatch, tmp_path):
    # package-owned files and system files must never be quarantined
    owned = tmp_path / "owned"
    owned.write_text("x")
    evil = tmp_path / "evil"
    evil.write_text("x")
    monkeypatch.setattr(quarantine.packages, "owner",
                        lambda f: ("pkg", None) if f == str(owned) else None)
    out = quarantine.files_to_quarantine("/usr/bin/python3",
                                         ["python3", str(owned), str(evil)])
    assert str(evil) in out
    assert str(owned) not in out
    assert "/usr/bin/python3" not in out
