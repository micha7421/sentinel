# Copyright 2026 micha7421
# Distributed under the terms of the GNU General Public License v3

EAPI=8

DISTUTILS_USE_PEP517=setuptools
PYTHON_COMPAT=( python3_{11..14} )

inherit desktop distutils-r1 systemd xdg

DESCRIPTION="Background security guard: ransomware and break-in protection"
HOMEPAGE="https://github.com/micha7421/sentinel"

if [[ ${PV} == 9999 ]]; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/micha7421/sentinel.git"
else
	SRC_URI="https://github.com/micha7421/sentinel/archive/refs/tags/v${PV}.tar.gz -> ${P}.gh.tar.gz"
	KEYWORDS="~amd64"
fi

LICENSE="GPL-3+"
SLOT="0"
IUSE="gui"

RDEPEND="
	dev-python/psutil[${PYTHON_USEDEP}]
	dev-python/watchdog[${PYTHON_USEDEP}]
	net-firewall/nftables
	sys-apps/util-linux
	x11-libs/libnotify
	gui? (
		dev-python/pyqt6[gui,widgets,${PYTHON_USEDEP}]
		sys-auth/polkit
	)
"

# Fill in where the program lives in the service files.
sentinel_template() {
	sed -e "s|@BINDIR@|${EPREFIX}/usr/bin|g" "data/${1}.in" > "${T}/${1}" || die
}

python_install_all() {
	distutils-r1_python_install_all

	sentinel_template sentinel.service
	systemd_dounit "${T}"/sentinel.service
	sentinel_template sentinel.initd
	newinitd "${T}"/sentinel.initd sentinel

	insinto /etc/sentinel
	newins config.example.toml config.toml
	keepdir /var/lib/sentinel /var/log/sentinel

	if use gui; then
		sentinel_template io.github.micha7421.sentinel.policy
		insinto /usr/share/polkit-1/actions
		doins "${T}"/io.github.micha7421.sentinel.policy
		sentinel_template sentinel.desktop
		domenu "${T}"/sentinel.desktop
		sentinel_template sentinel-tray.desktop
		insinto /etc/xdg/autostart
		doins "${T}"/sentinel-tray.desktop
	fi
}

pkg_postinst() {
	xdg_pkg_postinst

	if [[ -z ${REPLACING_VERSIONS} ]]; then
		elog "Start Sentinel and run it at every boot:"
		elog "  systemd: systemctl enable --now sentinel"
		elog "  OpenRC:  rc-update add sentinel default && rc-service sentinel start"
		elog
		elog "Settings: /etc/sentinel/config.toml"
		elog "If this PC has more than one user account, set 'user' there."
		elog
		elog "Safe tests:  sentinel test-ransomware  and  sentinel test-breakin  (as root)"
		use gui && elog "Window: search for \"Sentinel\" in the menu, or run: sentinel gui"
	else
		elog "Restart Sentinel to use the new version:"
		elog "  systemd: systemctl restart sentinel    OpenRC: rc-service sentinel restart"
	fi
}
