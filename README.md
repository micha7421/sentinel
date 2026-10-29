# 🛡️ Sentinel

A background security guard for Linux. First-class on **Gentoo** (Portage) and
**Arch-based** distros like **Tessera Linux** (pacman); works on KDE with
systemd or OpenRC.

## What it does (version 0.6)

**Ransomware guard**
- Places trap files (`!sentinel-trap-do-not-touch.docx`) in your folders.
  Ransomware encrypts everything, including the traps, and gets caught.
- Notices when many files suddenly change and look encrypted, or get
  renamed to strange endings like `.locked`.
- Freezes and kills the guilty program, moves it to quarantine, and shows a
  popup. Uses Portage's records so it never quarantines a real system program.

**Break-in guard**
- Watches for SSH password guessing and port scans.
- Blocks the attacker in the firewall (nftables), for a while, then lets go.
- Looks up where the attacker's IP comes from and whether it's a **VPN, Tor,
  a rented server or home internet**, using daily-updated lists plus optional
  online lookups. Can copy a ready-made abuse report for you.

**Spyware & sabotage guard**
- Warns the moment a program reads your secrets — password hashes
  (`/etc/shadow`), SSH private keys, saved WiFi passwords — or opens a decoy
  "password" file Sentinel plants as bait. Opening the bait gets the program
  stopped and quarantined.
- Warns when something adds itself to **autostart** (`~/.config/autostart`,
  systemd user units, cron, login scripts like `~/.bashrc`) — the trick USB
  malware uses to run again at every login.
- Catches **fork bombs** (a program that copies itself until the PC freezes)
  and freezes the runaway processes. Off by default, because compiling on
  Gentoo also starts many processes.

**System file check**
- Once a day, compares your installed programs (`/usr/bin`, PAM modules, ...)
  with the checksums your package manager recorded — Portage on Gentoo, pacman
  on Arch/Tessera — to spot secretly changed system files, and tells you the
  exact command (`emerge -1 …` or `pacman -S …`) to repair them.

**Supply-chain guard (Arch/pacman)**
- A pacman hook scans every package *before* it installs, looking inside its
  install script and files for danger signs: downloading and running code,
  editing sudoers or `ld.so.preload`, adding SUID bits, opening reverse shells,
  dropping into cron/PAM/autostart. It only warns by default; set
  `package_scan_block` to have a high-risk package stop the install. It always
  fails open — a scanner hiccup never blocks your updates.

**Security center & hardening score**
- One page listing every security tool on the PC with a green/red/grey status —
  Sentinel itself, the firewall (nftables/firewalld/ufw), Mullvad VPN,
  WireGuard, Tor, ClamAV, fail2ban, AppArmor/SELinux, the SSH server (warns if
  password login is on), disk encryption — plus one-click actions like
  connecting Mullvad or updating ClamAV's database.
- A single **hardening score (0–100)** with the most valuable fixes listed
  first, so you know what to improve next.

> Sentinel is an extra layer, not a replacement for **backups** or an
> antivirus. It does not catch every kind of malware (for example a program
> that only reads a few files). Keep backups.

## Install on Gentoo (with emerge)

Add the overlay (so updates come with your normal `emerge`), then install:

```bash
sudo eselect repository add sentinel git https://github.com/micha7421/sentinel.git
sudo emerge --sync sentinel
sudo emerge --ask app-antivirus/sentinel
```

The `gui` USE flag (on by default) installs the window and tray icon. Turn it
off for a server: `echo 'app-antivirus/sentinel -gui' | sudo tee /etc/portage/package.use/sentinel`.

## Install on Arch / Tessera Linux (with pacman)

A `PKGBUILD` is in `packaging/arch/`:

```bash
git clone https://github.com/micha7421/sentinel.git
cd sentinel/packaging/arch
makepkg -si
```

This pulls `python-psutil`, `python-watchdog`, `nftables`, `libnotify` and
`polkit` (plus `python-pyqt6` for the window), installs the systemd service and
the menu/tray entries, and places the config at `/etc/sentinel/config.toml`.

Then start it and run it at every boot:

```bash
sudo systemctl enable --now sentinel     # systemd
sudo rc-update add sentinel default && sudo rc-service sentinel start   # OpenRC
```

### Install without an overlay (any distro)

```bash
sudo emerge --ask dev-python/watchdog dev-python/psutil dev-python/pyqt6 \
    x11-libs/libnotify net-firewall/nftables
git clone https://github.com/micha7421/sentinel.git
cd sentinel && sudo ./install.sh
```

## The window

Search for **Sentinel** in the KDE menu, or click the shield in the system
tray (it starts automatically when you log in).

- 🟢 green shield: you are protected
- 🔴 red shield: a new alarm or break-in attempt, open the window to see it
- 🟠 orange shield: protection is off

Pages: **Overview** (status, the Gentoo system check, safe tests),
**Quarantine** (restore or delete caught programs), **Break-ins** (every
attack, where it came from, abuse report), **Activity** (history and log),
**Settings**. KDE asks for your password when you change something.

## Commands

| Command | What it does |
|---|---|
| `sentinel gui` | Opens the window |
| `sudo sentinel test-ransomware` | Safe test: fake ransomware in a throwaway folder |
| `sudo sentinel test-breakin` | Safe test: VPN/Tor check, fake SSH attack, port scan of this PC |
| `sudo sentinel test-threats` | Safe test: fake secret-reading, autostart drop, fork bomb |
| `sudo sentinel check-system` | Check system programs against the package manager |
| `sentinel security` | Show your security tools and hardening score |
| `sudo sentinel setup` | First-run setup: write config, enable the service |
| `sentinel scan-package FILE` | Scan a package for supply-chain risks |
| `sentinel lookup IP` | Who is behind an IP? (VPN, Tor, location, owner) |
| `sudo sentinel unblock IP` | Unblock an IP address |
| `sudo sentinel quarantine` | Lists quarantined programs |
| `sudo sentinel restore ID` / `delete ID` | Restore or delete a quarantined program |
| `systemctl status sentinel` / `journalctl -u sentinel` | Running? / the log |

Settings: `/etc/sentinel/config.toml`, or the Settings page in the window.

## Good to know

- Don't touch the trap files. If you delete one yourself, Sentinel raises an
  alarm (but Dolphin is on the allowlist, so nothing gets killed).
- On a home PC behind a router, attacks from the internet usually can't reach
  you, so most break-in entries will come from your own network or from tests.
- The attacker's location and network type are a good guess, not proof. Never
  attack back: it is illegal, and the IP is often an innocent, hacked computer.
- Sentinel spots malware by its **behaviour** (encrypting files, reading
  secrets, adding autostart, flooding processes), not by a virus signature, so
  it catches whole families of attacks — but a program that does none of those
  things can still slip by. It is a strong extra layer, not a complete
  antivirus, and not a substitute for backups.
- A trusted reader of your secrets is recognised by its real executable (and,
  on Gentoo, by Portage owning that file), not just its name — so malware that
  renames itself `baloo_file` or `sshd` to look harmless is still caught,
  because its binary sits in `/tmp` or your home folder, not in the system.

## Coming next

- [x] Ransomware guard, window and tray icon
- [x] Break-in guard with VPN/Tor check
- [x] Gentoo: ebuild/overlay and the Portage system check
- [x] Spyware guard: secret-reading, autostart persistence, fork bombs
- [x] Supply-chain guard: scan pacman packages before install
- [x] Security center with a hardening score and fix list
- [ ] Signed-package tamper detection (once the distro signs packages)

## Update

With the overlay: `sudo emerge --sync sentinel && sudo emerge -u app-antivirus/sentinel`.
Otherwise: `cd sentinel && git pull && sudo ./install.sh`.

## Uninstall

`sudo emerge --depclean app-antivirus/sentinel`, or `sudo ./uninstall.sh` if
you used the script.
