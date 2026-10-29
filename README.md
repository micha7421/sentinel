# 🛡️ Sentinel

A background security guard for Linux (made on Gentoo + KDE + systemd).

## What it does (version 0.1)

**Ransomware guard**
- Places trap files (`!sentinel-trap-do-not-touch.docx`) in your folders.
  Ransomware encrypts everything, including the traps, and gets caught.
- Notices when many files suddenly change and look encrypted, or get
  renamed to strange endings like `.locked`.
- Freezes and kills the guilty program, moves it to quarantine, and shows a
  popup on your desktop.

## Install (Gentoo)

```bash
sudo emerge --ask dev-python/watchdog dev-python/psutil x11-libs/libnotify
git clone https://github.com/YOUR-NAME/sentinel.git
cd sentinel
sudo ./install.sh
```

## Use it

| Command | What it does |
|---|---|
| `sudo sentinel test-popup` | Shows a test popup |
| `sudo sentinel test-ransomware` | Safe test: releases fake ransomware in a throwaway folder |
| `sudo sentinel quarantine` | Lists programs that were quarantined |
| `sudo sentinel restore ID` | Puts a program back (if it was a false alarm) |
| `sudo sentinel delete ID` | Deletes a quarantined program for good |
| `systemctl status sentinel` | Is Sentinel running? |
| `journalctl -u sentinel` | Sentinel's log |

Settings: `/etc/sentinel/config.toml` (then `sudo systemctl restart sentinel`).

## Good to know

- Don't touch the trap files. If you delete one yourself, Sentinel will raise an
  alarm (but your file manager Dolphin is on the allowlist, so nothing gets killed).
- Sentinel is an extra layer, not a replacement for **backups**. Keep backups!

## Coming next

- [ ] Break-in guard: detects login attempts and port scans, blocks the attacker,
      shows where the IP comes from and whether it's a VPN or Tor
- [ ] Security center menu: finds installed tools (Mullvad VPN, firewall,
      ClamAV, ...) and controls them from one place
- [ ] Nicer interface (tray icon / window)

## Uninstall

```bash
sudo ./uninstall.sh
```
