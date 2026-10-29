import pytest
from sentinel import packages


class FakeBackend:
    __name__ = "sentinel.portage_db"

    def available(self):
        return True

    def owner(self, p):
        return ("somepkg", None) if p == "/owned" else None

    def is_genuine(self, p):
        return ("somepkg", True)

    def check_system(self, slow=False):
        return {"time": 1, "seconds": 1, "checked": 3, "changed": [], "missing": []}

    def repair_command(self, pkgs):
        return "emerge -1 " + " ".join(pkgs)


@pytest.fixture
def one_backend(monkeypatch):
    monkeypatch.setattr(packages, "BACKENDS", [FakeBackend()])


def test_dispatch(one_backend):
    assert packages.available()
    assert packages.owner("/owned") == ("somepkg", None)
    assert packages.owner("/other") is None
    assert packages.is_genuine("/x")[1] is True
    assert packages.check_system()["checked"] == 3
    assert "emerge" in packages.repair_command(["a"])


def test_no_backend(monkeypatch):
    monkeypatch.setattr(packages, "BACKENDS", [])
    assert packages.available() is False
    assert packages.owner("/x") is None
    assert packages.is_genuine("/x") is None
    assert packages.check_system()["checked"] == 0
    assert packages.repair_command(["a"]) == ""
