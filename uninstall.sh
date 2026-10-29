#!/bin/sh
# Removes Sentinel. Run with: sudo ./uninstall.sh
set -e
[ "$(id -u)" -eq 0 ] || { echo "Please run with sudo"; exit 1; }
systemctl disable --now sentinel 2>/dev/null || true
rm -f /etc/systemd/system/sentinel.service /usr/local/bin/sentinel
rm -rf /opt/sentinel
systemctl daemon-reload
echo "Sentinel removed. Settings in /etc/sentinel and quarantine in"
echo "/var/lib/sentinel were kept. Delete them by hand if you want."
