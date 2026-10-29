import pytest
from sentinel import credential


class FakeProc:
    def __init__(self, exe, name):
        self._exe, self._name = exe, name

    def exe(self):
        return self._exe

    def name(self):
        return self._name


@pytest.fixture
def guard():
    g = credential.CredentialGuard({}, home="/home/x", watch={})
    g.watched = {"/etc/shadow": credential.SHADOW_READERS}
    return g


def test_genuine_reader_trusted(guard, monkeypatch):
    monkeypatch.setattr(credential, "_trusted_location", lambda exe: True)
    # baloo_file is a SYSTEM_READER and lives in a real system path
    proc = FakeProc("/usr/bin/baloo_file", "baloo_file")
    assert guard.is_trusted_reader(proc, "/etc/shadow") is True


def test_rename_trick_not_trusted(guard, monkeypatch):
    # malware named baloo_file but running from /tmp fails the location check
    monkeypatch.setattr(credential, "_trusted_location",
                        lambda exe: exe.startswith(("/usr/", "/bin/")))
    proc = FakeProc("/tmp/baloo_file", "baloo_file")
    assert guard.is_trusted_reader(proc, "/etc/shadow") is False


def test_unknown_reader_not_trusted(guard, monkeypatch):
    monkeypatch.setattr(credential, "_trusted_location", lambda exe: True)
    proc = FakeProc("/tmp/evil", "evil")
    assert guard.is_trusted_reader(proc, "/etc/shadow") is False


def test_shadow_reader_allowed(guard, monkeypatch):
    monkeypatch.setattr(credential, "_trusted_location", lambda exe: True)
    proc = FakeProc("/usr/bin/sudo", "sudo")
    assert guard.is_trusted_reader(proc, "/etc/shadow") is True


def test_trusted_location_fallback(monkeypatch):
    # with no package backend, system dirs are trusted, /tmp is not
    import sentinel.packages as packages
    monkeypatch.setattr(packages, "available", lambda: False)
    assert credential._trusted_location("/usr/bin/ssh") is True
    assert credential._trusted_location("/tmp/ssh") is False


def test_friendly():
    assert "password hashes" in credential.friendly("/etc/shadow")
    assert "SSH" in credential.friendly("/home/x/.ssh/id_rsa")
