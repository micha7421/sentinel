from sentinel import securitycenter, config


def tool(key, ok, installed=True):
    return {"key": key, "name": key, "installed": installed, "ok": ok,
            "state": "", "detail": "", "actions": []}


def test_any():
    assert securitycenter._any(None, True, False) is True
    assert securitycenter._any(False, False) is False
    assert securitycenter._any(None, None) is None


def test_score_perfect(monkeypatch):
    cfg = dict(config.DEFAULTS)
    tools = [tool("sentinel", True), tool("firewall", True), tool("luks", True),
             tool("sshd", True), tool("apparmor", True)]
    monkeypatch.setattr(securitycenter, "packages_ok", lambda: True)
    monkeypatch.setattr(securitycenter.shutil, "which", lambda *a: "/usr/bin/pacman")
    r = securitycenter.score(cfg, tools)
    assert r["score"] == 100
    assert r["recommendations"] == []


def test_score_penalises_and_ranks(monkeypatch):
    cfg = dict(config.DEFAULTS)
    cfg["credential_guard"] = False      # weight 2
    tools = [tool("sentinel", False),    # weight 3, biggest
             tool("firewall", True), tool("luks", True), tool("sshd", True)]
    monkeypatch.setattr(securitycenter, "packages_ok", lambda: True)
    monkeypatch.setattr(securitycenter.shutil, "which", lambda *a: None)
    r = securitycenter.score(cfg, tools)
    assert 0 < r["score"] < 100
    # highest-weight failure (Sentinel not running) is listed first
    assert "Sentinel" in r["recommendations"][0]["text"]


def test_score_ignores_not_applicable(monkeypatch):
    cfg = dict(config.DEFAULTS)
    # No clamav/mullvad tools present -> they must not drag the score down
    tools = [tool("sentinel", True), tool("firewall", True), tool("luks", True),
             tool("sshd", True)]
    monkeypatch.setattr(securitycenter, "packages_ok", lambda: True)
    monkeypatch.setattr(securitycenter.shutil, "which", lambda *a: None)
    r = securitycenter.score(cfg, tools)
    assert r["score"] == 100
