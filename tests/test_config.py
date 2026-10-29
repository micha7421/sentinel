import pytest
from sentinel import config


def test_defaults_are_valid():
    config.validate(dict(config.DEFAULTS))


@pytest.mark.parametrize("bad", [
    {"unknown_key": 1},
    {"burst_files": "lots"},        # wrong type
    {"canaries": 1},                # int where bool expected
    {"auto_kill": "yes"},
    {"burst_files": 0},             # below minimum
    {"watch_dirs": [1, 2]},         # list of non-strings
])
def test_validate_rejects(bad):
    cfg = dict(config.DEFAULTS)
    cfg.update(bad)
    with pytest.raises(ValueError):
        config.validate(cfg)


def test_toml_roundtrip(tmp_path):
    cfg = dict(config.DEFAULTS)
    cfg["burst_files"] = 42
    cfg["watch_dirs"] = ['~/Odd "quoted" dir', "~/Documents"]
    cfg["user"] = "alice"
    p = tmp_path / "c.toml"
    p.write_text(config.to_toml(cfg))
    loaded = config.load_raw(p)
    assert loaded["burst_files"] == 42
    assert loaded["watch_dirs"] == ['~/Odd "quoted" dir', "~/Documents"]
    assert loaded["user"] == "alice"
    config.validate(loaded)


def test_distro_name(tmp_path, monkeypatch):
    osr = tmp_path / "os-release"
    osr.write_text('NAME="Tessera"\nPRETTY_NAME="Tessera Linux"\nID=tessera\n')
    monkeypatch.setattr(config, "OS_RELEASE", osr)
    assert config.distro_name() == "Tessera Linux"


def test_distro_name_missing(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "OS_RELEASE", tmp_path / "nope")
    assert config.distro_name() == "Linux"
