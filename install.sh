#!/bin/sh
# Installs Sentinel without Portage. Run with: sudo ./install.sh
# (On Gentoo, installing with emerge is nicer, see the README.)
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Please run with sudo: sudo ./install.sh"; exit 1
fi
if [ -z "$SUDO_USER" ] || [ "$SUDO_USER" = root ]; then
    echo "Please run with sudo from your normal user account."; exit 1
fi
if [ -x /usr/bin/sentinel ]; then
    echo "Sentinel is already installed with emerge. Use emerge to update it."; exit 1
fi

echo "Checking requirements..."
missing=""
python3 -c "import watchdog" 2>/dev/null || missing="$missing dev-python/watchdog"
python3 -c "import psutil" 2>/dev/null || missing="$missing dev-python/psutil"
command -v notify-send >/dev/null || missing="$missing x11-libs/libnotify"
command -v nft >/dev/null || missing="$missing net-firewall/nftables"
if [ -n "$missing" ]; then
    echo "Missing packages. Install them first with:"
    echo "    sudo emerge --ask$missing"
    exit 1
fi
gui=yes
if ! python3 -c "from PyQt6 import QtWidgets" 2>/dev/null; then
    gui=no
    echo "Note: the Sentinel window needs PyQt6. To get it:"
    echo "    sudo emerge --ask dev-python/pyqt6"
    echo "Installing the background protection now; run this script again later."
    echo
fi

cd "$(dirname "$0")"
BINDIR=/usr/local/bin
template() {  # fill in where the program lives
    sed "s|@BINDIR@|$BINDIR|g" "data/$1.in"
}

echo "Copying program to /opt/sentinel..."
rm -rf /opt/sentinel
mkdir -p /opt/sentinel
cp -r sentinel /opt/sentinel/

printf '#!/bin/sh\nPYTHONPATH=/opt/sentinel exec python3 -m sentinel "$@"\n' > $BINDIR/sentinel
chmod 755 $BINDIR/sentinel

if [ ! -f /etc/sentinel/config.toml ]; then
    mkdir -p /etc/sentinel
    sed "s/^user = .*/user = \"$SUDO_USER\"/" config.example.toml > /etc/sentinel/config.toml
    echo "Created /etc/sentinel/config.toml for user $SUDO_USER"
fi

# Password rule for the window, menu entry, tray icon at login
mkdir -p /usr/share/polkit-1/actions
template io.github.micha7421.sentinel.policy > /usr/share/polkit-1/actions/io.github.micha7421.sentinel.policy
if [ "$gui" = yes ]; then
    mkdir -p /usr/share/applications /etc/xdg/autostart
    template sentinel.desktop > /usr/share/applications/sentinel.desktop
    template sentinel-tray.desktop > /etc/xdg/autostart/sentinel-tray.desktop
fi

if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    template sentinel.service > /etc/systemd/system/sentinel.service
    systemctl daemon-reload
    systemctl enable sentinel
    systemctl restart sentinel
else
    template sentinel.initd > /etc/init.d/sentinel
    chmod 755 /etc/init.d/sentinel
    rc-update add sentinel default
    rc-service sentinel restart
fi

echo
echo "Done! Sentinel is running and starts automatically on boot."
echo "Try it safely with:  sudo sentinel test-ransomware"
echo "                and  sudo sentinel test-breakin"
if [ "$gui" = yes ]; then
    echo "Open the window: search for \"Sentinel\" in the KDE menu."
    echo "(The tray icon starts automatically at your next login.)"
fi
