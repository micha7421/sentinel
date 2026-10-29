import json
import os
import pytest
from sentinel import firewall, crash, alarms, config


# ---------- firewall ----------

def test_set_for():
    assert firewall._set_for("1.2.3.4") == "blocked4"
    assert firewall._set_for("2001:db8::1") == "blocked6"


def test_block_rejects_bad_ip(monkeypatch):
    called = []
    monkeypatch.setattr(firewall, "_nft", lambda *a, **k: called.append(a))
    with pytest.raises(ValueError):
        firewall.block("1.2.3.4; flush ruleset", 1)
    assert called == []   # never reached nft


def test_block_valid_ip(monkeypatch):
    calls = []
    monkeypatch.setattr(firewall, "_nft", lambda *a, **k: calls.append(a) or "")
    firewall.block("203.0.113.7", 2)
    assert calls and "203.0.113.7" in " ".join(calls[0])


# ---------- crash guard ----------

class FakeInfo:
    def __init__(self, pid, ppid, name, uid):
        self.info = {"pid": pid, "ppid": ppid, "name": name,
                     "uids": type("U", (), {"real": uid})()}


def test_crash_detects_fork_bomb(monkeypatch):
    uid = os.getuid()
    procs = [FakeInfo(1000, 999, "sh", uid)]
    procs += [FakeInfo(2000 + i, 1000, "bomb", uid) for i in range(20)]
    monkeypatch.setattr(crash.psutil, "process_iter", lambda attrs: procs)
    g = crash.CrashGuard({}, test=True)
    g.limit = 15
    fired = []
    monkeypatch.setattr(g, "react", lambda *a: fired.append(a))
    g.check()
    assert fired and fired[0][1] == "bomb"


def test_crash_ignores_build_tools(monkeypatch):
    uid = os.getuid()
    procs = [FakeInfo(1000, 999, "make", uid)]
    procs += [FakeInfo(2000 + i, 1000, "cc1", uid) for i in range(50)]
    monkeypatch.setattr(crash.psutil, "process_iter", lambda attrs: procs)
    g = crash.CrashGuard({}, test=True)
    g.limit = 15
    fired = []
    monkeypatch.setattr(g, "react", lambda *a: fired.append(a))
    g.check()
    assert fired == []


def test_crash_skips_own_tree(monkeypatch):
    uid = os.getuid()
    mypid = os.getpid()
    procs = [FakeInfo(3000 + i, mypid, "bomb", uid) for i in range(30)]
    monkeypatch.setattr(crash.psutil, "process_iter", lambda attrs: procs)
    g = crash.CrashGuard({}, test=True)
    g.limit = 15
    fired = []
    monkeypatch.setattr(g, "react", lambda *a: fired.append(a))
    g.check()
    assert fired == []


# ---------- alarms ----------

def test_record_alarm(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "EVENTS_FILE", tmp_path / "events.jsonl")
    alarms.record_alarm("something bad", ["did a thing"], kind="credential", test=True)
    lines = (tmp_path / "events.jsonl").read_text().splitlines()
    entry = json.loads(lines[0])
    assert entry["reason"] == "something bad"
    assert entry["kind"] == "credential"
    assert entry["test"] is True
