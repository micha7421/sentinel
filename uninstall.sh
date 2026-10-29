#!/bin/sh
# Removes a Sentinel installed with install.sh. Run with: sudo ./uninstall.sh
# (If you installed with emerge, use: emerge --depclean app-antivirus/sentinel)
[ "$(id -u)" -eq 0 ] || { echo "Please run with sudo"; exit 1; }
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    systemctl disable --now sentinel 2>/dev/null
else
    rc-service sentinel stop 2>/dev/null
    rc-update del sentinel default 2>/dev/null
fi
nft delete table inet sentinel 2>/dev/null   # unblock everything Sentinel blocked
rm -f /etc/systemd/system/sentinel.service /etc/init.d/sentinel /usr/local/bin/sentinel \
      /usr/share/polkit-1/actions/io.github.micha7421.sentinel.policy \
      /usr/share/applications/sentinel.desktop /etc/xdg/autostart/sentinel-tray.desktop
rm -rf /opt/sentinel
command -v systemctl >/dev/null && systemctl daemon-reload 2>/dev/null
echo "Sentinel removed. Settings in /etc/sentinel and quarantine in"
echo "/var/lib/sentinel were kept. Delete them by hand if you want."
exit 0
