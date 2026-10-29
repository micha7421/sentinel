"""Sentinel window and tray icon (Qt, fits right into KDE).

The window runs as your normal user. It reads Sentinel's files directly and
asks for your password (through KDE's normal password dialog) only when it
has to change something: settings, quarantine, starting the service.
"""

import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

from PyQt6.QtCore import QPointF, QProcess, QSettings, QSize, Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPainterPath, QPixmap, QPolygonF
from PyQt6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QScrollArea, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QStackedWidget,
    QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import breakin, config, packages, quarantine, securitycenter

STATUS_TEXT = {"blocked": "Blocked in the firewall.", "expired": "The block has expired.",
               "unblocked": "Unblocked.", "not blocked": "Not blocked."}
GREEN, ORANGE, RED = QColor("#27ae60"), QColor("#f39c12"), QColor("#da4453")
# pkexec needs the full path. /usr/bin = installed with emerge,
# /usr/local/bin = installed with install.sh
SENTINEL_CMD = next((p for p in ("/usr/bin/sentinel", "/usr/local/bin/sentinel")
                     if os.path.exists(p)), "/usr/local/bin/sentinel")


# ---------- small helpers ----------

def shield_icon(color, size=64):
    """Draw a shield, so we don't depend on the icon theme."""
    pix = QPixmap(size, size)
    pix.fill(Qt.GlobalColor.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 64
    path = QPainterPath()
    path.moveTo(32 * s, 4 * s)
    path.lineTo(56 * s, 13 * s)
    path.cubicTo(56 * s, 36 * s, 47 * s, 52 * s, 32 * s, 60 * s)
    path.cubicTo(17 * s, 52 * s, 8 * s, 36 * s, 8 * s, 13 * s)
    path.closeSubpath()
    p.fillPath(path, color)
    # check mark (ok) or exclamation mark (problem)
    pen = p.pen()
    pen.setColor(QColor("white"))
    pen.setWidthF(5.5 * s)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(pen)
    if color == GREEN:
        p.drawPolyline(QPolygonF(_points(s, [(21, 32), (29, 40), (44, 24)])))
    else:
        p.drawLine(*_points(s, [(32, 18), (32, 36)]))
        p.drawPoint(*_points(s, [(32, 46)]))
    p.end()
    return QIcon(pix)


def _points(s, coords):
    return [QPointF(x * s, y * s) for x, y in coords]


def theme_icon(name, fallback=None):
    icon = QIcon.fromTheme(name)
    return icon if not icon.isNull() else (fallback or QIcon())


def service_state():
    """'active', 'inactive', 'failed', ... or 'missing' without systemd."""
    if not shutil.which("systemctl"):
        return "missing"
    r = subprocess.run(["systemctl", "is-active", "sentinel"],
                       capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def read_events():
    try:
        with open(config.EVENTS_FILE) as f:
            return [json.loads(line) for line in f if line.strip()]
    except (OSError, json.JSONDecodeError):
        return []


def time_ago(t):
    d = time.time() - t
    if d < 60:
        return "just now"
    if d < 3600:
        return f"{int(d // 60)} min ago"
    if d < 86400:
        return f"{int(d // 3600)} h ago"
    return time.strftime("%d %b %Y", time.localtime(t))


def heading(text):
    label = QLabel(text)
    font = label.font()
    font.setPointSizeF(font.pointSizeF() * 1.6)
    font.setBold(True)
    label.setFont(font)
    return label


def spin(low, high):
    box = QSpinBox()
    box.setRange(low, high)
    return box


def hrow(*parts):
    """A row of labels and input boxes: hrow("Alarm when", box, "files")"""
    row = QHBoxLayout()
    for part in parts:
        row.addWidget(QLabel(part) if isinstance(part, str) else part)
    row.addStretch()
    return row


def hint(text):
    label = QLabel(text)
    label.setWordWrap(True)
    label.setEnabled(False)  # greyed out, follows the KDE theme
    return label


class RootTask:
    """Runs `sentinel ...` as root through pkexec, without freezing the window."""

    def __init__(self, parent, args, on_done, on_output=None):
        self.proc = QProcess(parent)
        self.proc.setProcessChannelMode(QProcess.ProcessChannelMode.MergedChannels)
        self.output = ""
        self.on_done, self.on_output = on_done, on_output
        self.proc.readyReadStandardOutput.connect(self._read)
        self.proc.finished.connect(self._finished)
        if os.geteuid() == 0:
            program, arguments = sys.executable, ["-m", "sentinel"] + args
        elif config.INSTALLED:
            program, arguments = "pkexec", [SENTINEL_CMD] + args
        else:  # developing without installing
            program, arguments = sys.executable, ["-m", "sentinel"] + args
        self.proc.start(program, arguments)

    def _read(self):
        text = bytes(self.proc.readAllStandardOutput()).decode(errors="replace")
        self.output += text
        if self.on_output:
            self.on_output(text)

    def _finished(self, code, _status):
        # pkexec exits with 126/127 when the password dialog was cancelled.
        self.on_done(code == 0, self.output.strip(), code in (126, 127))


# ---------- pages ----------

class OverviewPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.setSpacing(16)

        # Big status card
        self.card = QFrame()
        self.card.setObjectName("card")
        card = QHBoxLayout(self.card)
        card.setContentsMargins(24, 20, 24, 20)
        self.shield = QLabel()
        card.addWidget(self.shield)
        text = QVBoxLayout()
        self.title = heading("")
        self.subtitle = QLabel()
        self.subtitle.setWordWrap(True)
        text.addWidget(self.title)
        text.addWidget(self.subtitle)
        card.addLayout(text, 1)
        self.action = QPushButton()
        self.action.clicked.connect(self.on_action)
        card.addWidget(self.action, 0, Qt.AlignmentFlag.AlignVCenter)
        layout.addWidget(self.card)

        # Numbers
        grid = QGridLayout()
        grid.setSpacing(12)
        self.stats = {}
        for i, (key, label) in enumerate([
                ("folders", "Protected folders"), ("alarms", "Threat alarms"),
                ("attacks", "Break-in attempts"), ("quarantine", "In quarantine"),
                ("last", "Last alarm")]):
            box = QFrame()
            box.setObjectName("stat")
            v = QVBoxLayout(box)
            value = QLabel("–")
            f = value.font()
            f.setPointSizeF(f.pointSizeF() * 1.8)
            f.setBold(True)
            value.setFont(f)
            v.addWidget(value)
            v.addWidget(hint(label))
            self.stats[key] = value
            grid.addWidget(box, 0, i)
        layout.addLayout(grid)

        # What's switched on
        self.features = QLabel()
        self.features.setTextFormat(Qt.TextFormat.RichText)
        group = QGroupBox("Protection")
        QVBoxLayout(group).addWidget(self.features)
        layout.addWidget(group)

        # Compare system programs with the package manager's records
        self.syscheck = QGroupBox("System file check")
        row = QHBoxLayout(self.syscheck)
        self.syscheck_text = QLabel()
        self.syscheck_text.setWordWrap(True)
        self.syscheck_text.setTextFormat(Qt.TextFormat.RichText)
        row.addWidget(self.syscheck_text, 1)
        self.syscheck_btn = QPushButton(theme_icon("system-search"), "Check now")
        self.syscheck_btn.setToolTip("Compares your system programs with what the "
                                     "package manager installed, to find changed ones.")
        self.syscheck_btn.clicked.connect(self.check_system)
        row.addWidget(self.syscheck_btn, 0, Qt.AlignmentFlag.AlignTop)
        self.syscheck.setVisible(packages.available())
        layout.addWidget(self.syscheck)

        # Tests
        tests = QGroupBox("Try it out (safe)")
        row = QHBoxLayout(tests)
        test_btn = QPushButton(theme_icon("tools-check-spelling"), "Run ransomware test")
        test_btn.setToolTip("Releases harmless fake ransomware in a throwaway "
                            "folder and checks that Sentinel stops it.")
        test_btn.clicked.connect(lambda: TestDialog(win, "test-ransomware").show())
        breakin_btn = QPushButton(theme_icon("network-firewall"), "Run break-in test")
        breakin_btn.setToolTip("Checks the VPN/Tor lists, simulates an SSH attack from "
                               "a test address and scans this PC.")
        breakin_btn.clicked.connect(lambda: TestDialog(win, "test-breakin").show())
        threats_btn = QPushButton(theme_icon("security-low"), "Run threat test")
        threats_btn.setToolTip("Safely checks the credential, persistence and crash "
                               "guards in a throwaway folder (nothing real is touched).")
        threats_btn.clicked.connect(lambda: TestDialog(win, "test-threats").show())
        popup_btn = QPushButton(theme_icon("preferences-desktop-notification"), "Show test popup")
        popup_btn.clicked.connect(lambda: RootTask(self, ["test-popup"], lambda *a: None))
        row.addWidget(test_btn)
        row.addWidget(breakin_btn)
        row.addWidget(threats_btn)
        row.addWidget(popup_btn)
        row.addStretch()
        layout.addWidget(tests)
        layout.addStretch()

    def refresh(self):
        state = self.win.state
        cfg = self.win.cfg
        folders = [d for d in cfg["watch_dirs"]
                   if config.expand(d, os.path.expanduser("~")).is_dir()]
        unseen = self.win.unseen_alarms()

        if state != "active":
            color, title = ORANGE, "Protection is off"
            sub = {"missing": "systemd was not found.",
                   "failed": "Sentinel crashed. See the Activity page for the log."}.get(
                state, "Sentinel is not running, your files are not protected.")
            self.action.setText("Start protection")
            self.action.setVisible(state != "missing")
        elif not folders:
            color, title = ORANGE, "No folders to protect"
            sub = "None of the folders in Settings exist. Add a folder there."
            self.action.setText("Open settings")
            self.action.setVisible(True)
        elif unseen:
            color, title = RED, f"{len(unseen)} new alarm{'s' * (len(unseen) > 1)}"
            sub = unseen[-1]["reason"] + "\n" + "\n".join(unseen[-1]["actions"])
            self.action.setText("Mark as seen")
            self.action.setVisible(True)
        else:
            color, title = GREEN, "You are protected"
            sub = f"Sentinel is watching {len(folders)} folders for ransomware"
            sub += " and your network for break-ins." if cfg["breakin_guard"] else "."
            self.action.setVisible(False)

        self.shield.setPixmap(shield_icon(color, 72).pixmap(72, 72))
        self.title.setText(title)
        self.subtitle.setText(sub)
        tint = QColor(color)
        tint.setAlpha(40)
        self.card.setStyleSheet(
            f"#card {{ background: rgba({tint.red()},{tint.green()},{tint.blue()},{tint.alpha()});"
            f" border: 1px solid {color.name()}; border-radius: 10px; }}")

        real = [e for e in self.win.events if not e.get("test")]
        recent = [e for e in real if e["time"] > time.time() - 30 * 86400]
        self.stats["folders"].setText(str(len(folders)))
        self.stats["alarms"].setText(str(len(recent)))
        attacks = [a for a in self.win.attacks if not a.get("test")
                   and a["time"] > time.time() - 30 * 86400]
        self.stats["attacks"].setText(str(len(attacks)))
        self.stats["quarantine"].setText(str(len(quarantine.list_items())))
        times = [e["time"] for e in real] + [a["time"] for a in self.win.attacks
                                             if not a.get("test")]
        self.stats["last"].setText(time_ago(max(times)) if times else "never")

        def onoff(v):
            return "<b style='color:#27ae60'>On</b>" if v else "<b style='color:#da4453'>Off</b>"
        self.features.setText(
            f"Trap files: {onoff(cfg['canaries'])} &nbsp;&nbsp; "
            f"Stop ransomware automatically: {onoff(cfg['auto_kill'])} &nbsp;&nbsp; "
            f"Quarantine: {onoff(cfg['auto_quarantine'])}<br>"
            f"Alarm when {cfg['burst_files']} files change within "
            f"{cfg['window_seconds']} seconds and look encrypted.<br>"
            f"Break-in guard: {onoff(cfg['breakin_guard'])} &nbsp;&nbsp; "
            f"Block attackers: {onoff(cfg['auto_block'])} &nbsp;&nbsp; "
            f"VPN/Tor check: <b style='color:#27ae60'>On</b><br>"
            f"Credential guard: {onoff(cfg['credential_guard'])} &nbsp;&nbsp; "
            f"Autostart guard: {onoff(cfg['persistence_guard'])} &nbsp;&nbsp; "
            f"Fork-bomb guard: {onoff(cfg['crash_guard'])}")
        self.refresh_syscheck()

    def refresh_syscheck(self):
        if not packages.available():
            return
        try:
            r = json.loads(config.INTEGRITY_FILE.read_text())
        except (OSError, ValueError):
            self.syscheck_text.setText("Not checked yet. Sentinel checks once a day, "
                                       "or click <b>Check now</b>.")
            return
        bad = r["changed"] + r["missing"]
        when = time_ago(r["time"])
        if not bad:
            self.syscheck_text.setText(
                f"✅ Last check {when}: all {r['checked']} system programs match "
                f"what {packages.name()} installed.")
        else:
            pkgs = sorted({b["package"] for b in bad})
            files = "<br>".join(f"&nbsp;&nbsp;{b['path']} ({b['package']})" for b in bad[:6])
            self.syscheck_text.setText(
                f"<b style='color:#da4453'>⚠️ Last check {when}: {len(r['changed'])} changed, "
                f"{len(r['missing'])} missing</b><br>{files}<br>"
                f"Reinstall them with: <code>{packages.repair_command(pkgs[:6])}</code>")

    def check_system(self):
        self.syscheck_btn.setEnabled(False)
        self.syscheck_text.setText("Checking… (this can take a minute)")

        def done(ok, output, cancelled):
            self.syscheck_btn.setEnabled(True)
            if not ok and not cancelled:
                QMessageBox.warning(self, "Sentinel", output)
            self.refresh_syscheck()
        self.win.tasks.append(RootTask(self, ["check-system"], done))

    def on_action(self):
        if self.win.state != "active":
            self.win.start_service()
        elif self.action.text() == "Open settings":
            self.win.go("Settings")
        else:
            self.win.mark_seen()


class QuarantinePage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.addWidget(heading("Quarantine"))
        layout.addWidget(hint("Programs Sentinel caught are locked away here and "
                              "can't run. If one was a false alarm, restore it."))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Program", "Came from", "When", "Why"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.empty = QLabel("Nothing in quarantine. 🎉")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.table)
        layout.addWidget(self.empty)
        row = QHBoxLayout()
        row.addStretch()
        self.restore_btn = QPushButton(theme_icon("edit-undo"), "Restore")
        self.delete_btn = QPushButton(theme_icon("edit-delete"), "Delete forever")
        self.restore_btn.clicked.connect(lambda: self.act("restore"))
        self.delete_btn.clicked.connect(lambda: self.act("delete"))
        row.addWidget(self.restore_btn)
        row.addWidget(self.delete_btn)
        layout.addLayout(row)
        self.items = []

    def refresh(self):
        self.items = quarantine.list_items()
        self.table.setRowCount(len(self.items))
        for r, item in enumerate(self.items):
            name = os.path.basename(item["original"])
            for c, text in enumerate([name, os.path.dirname(item["original"]),
                                      item["time"], item["reason"]]):
                cell = QTableWidgetItem(text)
                cell.setToolTip(text)
                self.table.setItem(r, c, cell)
        self.table.resizeColumnsToContents()
        has = bool(self.items)
        self.table.setVisible(has)
        self.empty.setVisible(not has)
        self.restore_btn.setEnabled(has)
        self.delete_btn.setEnabled(has)

    def act(self, what):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Sentinel", "Select a program first.")
            return
        item = self.items[row]
        name = os.path.basename(item["original"])
        if what == "restore":
            question = (f"Put '{name}' back to {item['original']}?\n\n"
                        "Only do this if you are sure it is safe.")
        else:
            question = f"Delete '{name}' forever? This can't be undone."
        if QMessageBox.question(self, "Sentinel", question) != QMessageBox.StandardButton.Yes:
            return
        self.win.run_root([what, item["id"]], f"{name}: {what} done.")


class ActivityPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.addWidget(heading("Activity"))
        self.alarms = QListWidget()
        self.alarms.setWordWrap(True)
        self.alarms.setAlternatingRowColors(True)
        group = QGroupBox("Alarms")
        QVBoxLayout(group).addWidget(self.alarms)
        layout.addWidget(group, 2)
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(QFont("monospace"))
        group = QGroupBox("Log (newest at the bottom)")
        QVBoxLayout(group).addWidget(self.log)
        layout.addWidget(group, 1)

    def refresh(self):
        self.alarms.clear()
        for e in reversed(self.win.events):
            when = time.strftime("%d %b %Y %H:%M", time.localtime(e["time"]))
            tag = "  (test)" if e.get("test") else ""
            item = QListWidgetItem(f"{when}{tag}\n{e['reason']}\n" + "\n".join(e["actions"]))
            item.setIcon(shield_icon(ORANGE if e.get("test") else RED, 32))
            self.alarms.addItem(item)
        if not self.win.events:
            self.alarms.addItem("No alarms yet.")
        try:
            with open(config.LOG_FILE) as f:
                lines = f.readlines()[-300:]
            text = "".join(lines)
        except OSError:
            text = f"Can't read {config.LOG_FILE}"
        if text != self.log.toPlainText():
            self.log.setPlainText(text)
            self.log.verticalScrollBar().setValue(self.log.verticalScrollBar().maximum())


class BreakinsPage(QWidget):
    KIND_NAMES = {"tor": "🧅 Tor", "vpn": "🕶️ VPN", "hosting": "🖥️ Rented server",
                  "home": "🏠 Home internet", "local": "🏡 Your network",
                  "test": "🧪 Test", "unknown": "❔ Unknown"}

    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.addWidget(heading("Break-in attempts"))
        layout.addWidget(hint(
            "Password guessing over SSH and port scans (someone looking for a way in). "
            "Attackers are blocked in the firewall. Behind a home router, attacks from "
            "the internet usually can't reach you, so most entries will come from your "
            "own network or from tests."))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["When", "IP address", "Attack", "Where from", "Network", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.doubleClicked.connect(self.details)
        self.empty = QLabel("No break-in attempts. 🎉")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.table)
        layout.addWidget(self.empty)
        row = QHBoxLayout()
        self.show_tests = QCheckBox("Show tests")
        self.show_tests.toggled.connect(self.refresh)
        row.addWidget(self.show_tests)
        row.addStretch()
        self.details_btn = QPushButton(theme_icon("documentinfo"), "Details && report…")
        self.details_btn.clicked.connect(self.details)
        self.unblock_btn = QPushButton(theme_icon("dialog-ok-apply"), "Unblock")
        self.unblock_btn.clicked.connect(self.unblock)
        row.addWidget(self.details_btn)
        row.addWidget(self.unblock_btn)
        layout.addLayout(row)
        self.rows = []

    def refresh(self):
        attacks = self.win.attacks
        if not self.show_tests.isChecked():
            attacks = [a for a in attacks if not a.get("test")]
        self.rows = list(reversed(attacks))
        self.table.setRowCount(len(self.rows))
        for r, a in enumerate(self.rows):
            info = a["info"]
            where = ", ".join(p for p in (info.get("location"), info.get("isp")) if p) or "–"
            status = {"blocked": f"🚫 blocked until "
                                 f"{time.strftime('%H:%M %d %b', time.localtime(a['blocked_until']))}",
                      "expired": "block expired", "unblocked": "unblocked",
                      "not blocked": "not blocked"}[a["status"]]
            cells = [time.strftime("%d %b %H:%M", time.localtime(a["time"])), a["ip"],
                     a["attack"], where, self.KIND_NAMES.get(info["kind"], info["kind"]), status]
            for c, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setToolTip(info["label"] if c == 4 else text)
                self.table.setItem(r, c, cell)
        self.table.resizeColumnsToContents()
        has = bool(self.rows)
        self.table.setVisible(has)
        self.empty.setVisible(not has)
        self.details_btn.setEnabled(has)
        self.unblock_btn.setEnabled(has)

    def selected(self):
        row = self.table.currentRow()
        if row < 0:
            QMessageBox.information(self, "Sentinel", "Select an attack first.")
            return None
        return self.rows[row]

    def details(self):
        a = self.selected()
        if not a:
            return
        info = a["info"]
        when = time.strftime("%d %b %Y %H:%M:%S %Z", time.localtime(a["time"]))
        report = (f"Hello,\n\nthe IP address {a['ip']} from your network attacked my "
                  f"computer.\n\nAttack: {a['attack']} ({a['detail']})\nTime: {when}\n\n"
                  "Please look into it.\n")
        text = (f"<h3>{a['attack']} from {a['ip']}</h3>"
                f"<p>{a['detail']}<br>{when}</p>"
                f"<p><b>{info['label']}</b></p><table>"
                + "".join(f"<tr><td><b>{k}</b>&nbsp;&nbsp;</td><td>{v}</td></tr>" for k, v in [
                    ("Location", info.get("location") or "–"),
                    ("Provider", info.get("isp") or "–"),
                    ("Network", info.get("network") or "–"),
                    ("Report to", info.get("abuse_email") or "–")])
                + "</table>")
        if info.get("abuse_email"):
            text += ("<p>You can report the attack to the provider's abuse address. "
                     "<b>Copy report</b> puts a ready-made e-mail on your clipboard.</p>")
        text += ("<p><i>Location and network type are a good guess, not proof. "
                 "Never attack back: that is illegal, and the IP often belongs to an "
                 "innocent, hacked computer.</i></p>")
        box = QMessageBox(self)
        box.setWindowTitle("Attack details")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(text)
        copy = None
        if info.get("abuse_email"):
            copy = box.addButton("Copy report", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if copy is not None and box.clickedButton() == copy:
            QApplication.clipboard().setText(f"To: {info['abuse_email']}\n\n{report}")
            self.win.statusBar().showMessage("Report copied to the clipboard.", 6000)

    def unblock(self):
        a = self.selected()
        if not a:
            return
        if a["status"] != "blocked":
            QMessageBox.information(self, "Sentinel", f"{a['ip']} is not blocked.")
            return
        if QMessageBox.question(self, "Sentinel", f"Unblock {a['ip']}?") == \
                QMessageBox.StandardButton.Yes:
            self.win.run_root(["unblock", a["ip"]], f"{a['ip']} unblocked.")


class SecurityCenterPage(QWidget):
    """One place to see every security tool on the PC and its state."""
    DOT = {True: "#27ae60", False: "#da4453", None: "#999999"}

    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.addWidget(heading("Security center"))

        # Hardening score header
        self.score_box = QFrame()
        self.score_box.setObjectName("card")
        sb = QHBoxLayout(self.score_box)
        sb.setContentsMargins(20, 14, 20, 14)
        self.score_num = QLabel("–")
        f = self.score_num.font()
        f.setPointSizeF(f.pointSizeF() * 2.4)
        f.setBold(True)
        self.score_num.setFont(f)
        sb.addWidget(self.score_num)
        col = QVBoxLayout()
        col.addWidget(QLabel("<b>Hardening score</b>"))
        self.score_bar = QProgressBar()
        self.score_bar.setRange(0, 100)
        self.score_bar.setTextVisible(False)
        self.score_bar.setFixedHeight(10)
        col.addWidget(self.score_bar)
        self.score_hint = hint("")
        col.addWidget(self.score_hint)
        sb.addLayout(col, 1)
        layout.addWidget(self.score_box)

        layout.addWidget(hint("Your security tools in one place. A green dot means "
                              "good, red means it needs attention, grey means it is "
                              "not installed."))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.body = QWidget()
        self.list = QVBoxLayout(self.body)
        self.list.setContentsMargins(0, 0, 8, 0)
        self.list.addStretch()
        scroll.setWidget(self.body)
        layout.addWidget(scroll, 1)
        self._sig = None

    def refresh(self):
        tools = securitycenter.collect()
        s = securitycenter.score(self.win.cfg, tools)
        color = GREEN if s["score"] >= 80 else (ORANGE if s["score"] >= 55 else RED)
        self.score_num.setText(str(s["score"]))
        self.score_num.setStyleSheet(f"color: {color.name()};")
        self.score_bar.setValue(s["score"])
        self.score_bar.setStyleSheet(
            f"QProgressBar {{ border: none; background: palette(mid); border-radius: 5px; }}"
            f"QProgressBar::chunk {{ background: {color.name()}; border-radius: 5px; }}")
        if s["recommendations"]:
            top = s["recommendations"][0]
            self.score_hint.setText(f"Biggest win: {top['how']}")
        else:
            self.score_hint.setText("Everything that applies to this PC is in good shape. 🎉")

        sig = [(t["key"], t["state"], t["ok"], len(t["actions"])) for t in tools]
        sig.append(s["score"])
        if sig == self._sig:
            return  # nothing changed, keep the buttons as they are
        self._sig = sig

        while self.list.count() > 1:  # drop everything but the trailing stretch
            item = self.list.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for t in tools:
            card = QFrame()
            card.setObjectName("stat")
            row = QHBoxLayout(card)
            dot = QLabel("●")
            dot.setStyleSheet(f"color: {self.DOT[t['ok']]}; font-size: 20px;")
            row.addWidget(dot, 0, Qt.AlignmentFlag.AlignTop)
            text = QVBoxLayout()
            title = QLabel(f"<b>{t['name']}</b> — {t['state']}")
            title.setTextFormat(Qt.TextFormat.RichText)
            text.addWidget(title)
            if t["detail"]:
                text.addWidget(hint(t["detail"]))
            row.addLayout(text, 1)
            for action in t["actions"]:
                btn = QPushButton(action["label"])
                btn.clicked.connect(lambda _=False, a=action: self.run(a))
                row.addWidget(btn, 0, Qt.AlignmentFlag.AlignVCenter)
            self.list.insertWidget(self.list.count() - 1, card)

    def run(self, action):
        self._sig = None  # force a redraw after it runs
        self.win.run_tool_action(action)


class SettingsPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        outer = QVBoxLayout(self)
        outer.addWidget(heading("Settings"))
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(0, 0, 8, 0)
        scroll.setWidget(content)
        outer.addWidget(scroll, 1)

        group = QGroupBox("Protected folders")
        v = QVBoxLayout(group)
        self.folders = QListWidget()
        self.folders.setMinimumHeight(110)
        v.addWidget(self.folders)
        v.addLayout(self.list_buttons(self.folders, self.add_folder))
        layout.addWidget(group, 1)

        group = QGroupBox("What to do")
        v = QVBoxLayout(group)
        self.canaries = QCheckBox("Place trap files in protected folders (recommended)")
        self.auto_kill = QCheckBox("Stop ransomware automatically (otherwise only freeze it and warn)")
        self.auto_quarantine = QCheckBox("Move caught programs to quarantine")
        for box in (self.canaries, self.auto_kill, self.auto_quarantine):
            v.addWidget(box)
        self.burst = spin(5, 1000)
        self.window_secs = spin(1, 120)
        v.addLayout(hrow("Alarm when", self.burst, "files change within",
                         self.window_secs, "seconds"))
        v.addWidget(hint("Lower numbers react faster but can cause false alarms."))
        layout.addWidget(group)

        group = QGroupBox("Trusted programs (never stopped)")
        v = QVBoxLayout(group)
        self.allow = QListWidget()
        self.allow.setMinimumHeight(110)
        v.addWidget(self.allow)
        v.addLayout(self.list_buttons(self.allow, self.add_program))
        layout.addWidget(group, 1)

        group = QGroupBox("Break-in guard")
        v = QVBoxLayout(group)
        self.breakin_on = QCheckBox("Watch for SSH password guessing and port scans")
        self.auto_block = QCheckBox("Block attackers in the firewall (nftables)")
        self.ip_lookup = QCheckBox("Look up where attackers come from "
                                   "(asks ipinfo.io and rdap.org about the attacker's IP)")
        for box in (self.breakin_on, self.auto_block, self.ip_lookup):
            v.addWidget(box)
        self.block_hours = spin(1, 720)
        self.ssh_failures = spin(2, 100)
        self.ssh_minutes = spin(1, 1440)
        self.scan_ports = spin(5, 1000)
        self.scan_seconds = spin(1, 600)
        v.addLayout(hrow("Block attackers for", self.block_hours, "hours"))
        v.addLayout(hrow("SSH attack:", self.ssh_failures, "failed logins within",
                         self.ssh_minutes, "minutes"))
        v.addLayout(hrow("Port scan:", self.scan_ports, "different ports within",
                         self.scan_seconds, "seconds"))
        v.addWidget(QLabel("Trusted addresses, never blocked (e.g. 192.168.1.10 or 192.168.1.0/24):"))
        self.trusted = QListWidget()
        self.trusted.setMinimumHeight(80)
        self.trusted.setMaximumHeight(120)
        v.addWidget(self.trusted)
        v.addLayout(self.list_buttons(self.trusted, self.add_trusted))
        layout.addWidget(group)

        group = QGroupBox("Spyware && sabotage guard")
        v = QVBoxLayout(group)
        self.credential_guard = QCheckBox("Warn when something reads your secrets "
                                          "(/etc/shadow, SSH keys, WiFi passwords)")
        self.credential_bait = QCheckBox("Plant decoy password files as bait")
        self.credential_kill = QCheckBox("Stop a program that opens a decoy file")
        self.persistence_guard = QCheckBox("Warn when something adds itself to autostart, "
                                           "cron or a login script")
        self.crash_guard = QCheckBox("Catch fork bombs (process explosions) — "
                                     "may misfire while compiling, off by default")
        for box in (self.credential_guard, self.credential_bait, self.credential_kill,
                    self.persistence_guard, self.crash_guard):
            v.addWidget(box)
        layout.addWidget(group)

        group = QGroupBox("System integrity")
        v = QVBoxLayout(group)
        self.system_check = QCheckBox("Check system programs against the package "
                                      "manager's records once a day")
        v.addWidget(self.system_check)
        self.package_scan = QCheckBox("Scan packages for supply-chain risks before "
                                      "they install (pacman)")
        self.package_scan_block = QCheckBox("Refuse to install a package flagged "
                                            "high-risk (otherwise only warn)")
        if packages.name() == "pacman":
            v.addWidget(self.package_scan)
            v.addWidget(self.package_scan_block)
        group.setVisible(packages.available())
        layout.addWidget(group)

        row = QHBoxLayout()
        row.addStretch()
        undo = QPushButton(theme_icon("edit-undo"), "Undo changes")
        undo.clicked.connect(self.load)
        save = QPushButton(theme_icon("document-save"), "Save")
        save.setDefault(True)
        save.clicked.connect(self.save)
        row.addWidget(undo)
        row.addWidget(save)
        outer.addLayout(row)
        self.loaded = False

    def list_buttons(self, lst, add):
        row = QHBoxLayout()
        a = QPushButton(theme_icon("list-add"), "Add…")
        a.clicked.connect(add)
        r = QPushButton(theme_icon("list-remove"), "Remove")
        r.clicked.connect(lambda: [lst.takeItem(lst.row(i)) for i in lst.selectedItems()])
        row.addWidget(a)
        row.addWidget(r)
        row.addStretch()
        return row

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Protect a folder", os.path.expanduser("~"))
        if folder:
            home = os.path.expanduser("~")
            if folder.startswith(home + os.sep):
                folder = "~" + folder[len(home):]
            self.folders.addItem(folder)

    def add_program(self):
        name, ok = QInputDialog.getText(self, "Trust a program",
                                        "Program name (as shown in the task manager):")
        if ok and name.strip():
            self.allow.addItem(name.strip())

    def add_trusted(self):
        text, ok = QInputDialog.getText(self, "Trust an address",
                                        "IP address or network (e.g. 192.168.1.0/24):")
        if not ok or not text.strip():
            return
        try:
            ipaddress.ip_network(text.strip(), strict=False)
        except ValueError:
            QMessageBox.warning(self, "Sentinel", f"'{text}' is not an IP address.")
            return
        self.trusted.addItem(text.strip())

    def refresh(self):
        if not self.loaded:  # don't overwrite changes the user is making
            self.load()

    def load(self):
        cfg = self.win.cfg
        self.folders.clear()
        self.folders.addItems(cfg["watch_dirs"])
        self.allow.clear()
        self.allow.addItems(cfg["allowlist"])
        self.canaries.setChecked(cfg["canaries"])
        self.auto_kill.setChecked(cfg["auto_kill"])
        self.auto_quarantine.setChecked(cfg["auto_quarantine"])
        self.burst.setValue(cfg["burst_files"])
        self.window_secs.setValue(cfg["window_seconds"])
        self.breakin_on.setChecked(cfg["breakin_guard"])
        self.auto_block.setChecked(cfg["auto_block"])
        self.ip_lookup.setChecked(cfg["ip_lookup"])
        self.block_hours.setValue(cfg["block_hours"])
        self.ssh_failures.setValue(cfg["ssh_max_failures"])
        self.ssh_minutes.setValue(cfg["ssh_window_minutes"])
        self.scan_ports.setValue(cfg["scan_ports"])
        self.scan_seconds.setValue(cfg["scan_window_seconds"])
        self.trusted.clear()
        self.trusted.addItems(cfg["trusted_ips"])
        self.credential_guard.setChecked(cfg["credential_guard"])
        self.credential_bait.setChecked(cfg["credential_bait"])
        self.credential_kill.setChecked(cfg["credential_auto_kill"])
        self.persistence_guard.setChecked(cfg["persistence_guard"])
        self.crash_guard.setChecked(cfg["crash_guard"])
        self.system_check.setChecked(cfg["system_check"])
        self.package_scan.setChecked(cfg["package_scan"])
        self.package_scan_block.setChecked(cfg["package_scan_block"])
        self.loaded = True

    def save(self):
        cfg = dict(self.win.cfg)
        cfg.update({
            "watch_dirs": [self.folders.item(i).text() for i in range(self.folders.count())],
            "allowlist": [self.allow.item(i).text() for i in range(self.allow.count())],
            "canaries": self.canaries.isChecked(),
            "auto_kill": self.auto_kill.isChecked(),
            "auto_quarantine": self.auto_quarantine.isChecked(),
            "burst_files": self.burst.value(),
            "window_seconds": self.window_secs.value(),
            "breakin_guard": self.breakin_on.isChecked(),
            "auto_block": self.auto_block.isChecked(),
            "ip_lookup": self.ip_lookup.isChecked(),
            "block_hours": self.block_hours.value(),
            "ssh_max_failures": self.ssh_failures.value(),
            "ssh_window_minutes": self.ssh_minutes.value(),
            "scan_ports": self.scan_ports.value(),
            "scan_window_seconds": self.scan_seconds.value(),
            "trusted_ips": [self.trusted.item(i).text() for i in range(self.trusted.count())],
            "credential_guard": self.credential_guard.isChecked(),
            "credential_bait": self.credential_bait.isChecked(),
            "credential_auto_kill": self.credential_kill.isChecked(),
            "persistence_guard": self.persistence_guard.isChecked(),
            "crash_guard": self.crash_guard.isChecked(),
            "system_check": self.system_check.isChecked(),
            "package_scan": self.package_scan.isChecked(),
            "package_scan_block": self.package_scan_block.isChecked(),
        })
        fd, path = tempfile.mkstemp(prefix="sentinel-", suffix=".toml")
        with os.fdopen(fd, "w") as f:
            f.write(config.to_toml(cfg))

        def done():
            os.unlink(path)
            self.loaded = False
        self.win.run_root(["apply-config", path], "Settings saved. Sentinel restarted.",
                          after=done)


# ---------- test dialog ----------

class TestDialog(QDialog):
    def __init__(self, parent, command):
        super().__init__(parent)
        self.setWindowTitle({"test-ransomware": "Ransomware test",
                             "test-threats": "Threat test (credentials, autostart, crash)",
                             "test-breakin": "Break-in test"}[command])
        self.resize(640, 360)
        layout = QVBoxLayout(self)
        self.status = QLabel("Running the test… (enter your password if asked)")
        layout.addWidget(self.status)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setFont(QFont("monospace"))
        layout.addWidget(self.out)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)
        self.task = RootTask(self, [command], self.done, self.out.insertPlainText)

    def done(self, ok, output, cancelled):
        if cancelled:
            self.status.setText("Cancelled.")
        elif ok:
            self.status.setText("✅ Test passed.")
        else:
            self.status.setText("❌ Test failed, see the output below.")
        self.parent().refresh()


# ---------- main window ----------

class MainWindow(QMainWindow):
    PAGES = [("Overview", "security-high"), ("Quarantine", "folder-locked"),
             ("Break-ins", "network-firewall"), ("Security", "preferences-security"),
             ("Activity", "view-history"), ("Settings", "configure")]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel")
        self.setWindowIcon(shield_icon(GREEN))
        self.resize(900, 620)
        self.settings = QSettings("Sentinel", "Sentinel")
        self.state, self.events, self.cfg = "unknown", [], config.load_raw()
        self.attacks = []
        self.tasks = []
        self.tray = None
        self.known_alarms = len(read_events())
        self.known_attacks = len(breakin.read_attacks())

        central = QWidget()
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.nav.setIconSize(QSize(22, 22))
        self.stack = QStackedWidget()
        self.pages = [OverviewPage(self), QuarantinePage(self), BreakinsPage(self),
                      SecurityCenterPage(self), ActivityPage(self), SettingsPage(self)]
        for (name, icon), page in zip(self.PAGES, self.pages):
            self.nav.addItem(QListWidgetItem(theme_icon(icon), name))
            wrapper = QWidget()
            QVBoxLayout(wrapper).addWidget(page)
            wrapper.layout().setContentsMargins(20, 16, 20, 16)
            self.stack.addWidget(wrapper)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.currentRowChanged.connect(lambda _: self.refresh())
        self.nav.setCurrentRow(0)
        side = QWidget()
        side.setObjectName("side")
        v = QVBoxLayout(side)
        v.setContentsMargins(0, 14, 0, 0)
        brand = QHBoxLayout()
        brand.setContentsMargins(14, 0, 14, 4)
        logo = QLabel()
        logo.setPixmap(shield_icon(GREEN, 28).pixmap(28, 28))
        name = QLabel("Sentinel")
        f = name.font()
        f.setPointSizeF(f.pointSizeF() * 1.3)
        f.setBold(True)
        name.setFont(f)
        brand.addWidget(logo)
        brand.addWidget(name, 1)
        v.addLayout(brand)
        distro = QLabel(config.distro_name())
        distro.setContentsMargins(14, 0, 14, 6)
        distro.setEnabled(False)  # subtle, follows the theme
        v.addWidget(distro)
        v.addWidget(self.nav)
        h.addWidget(side)
        h.addWidget(self.stack, 1)
        self.setCentralWidget(central)
        self.setStyleSheet("""
            #side, #nav { background: palette(base); border: none; }
            #nav { padding-top: 8px; }
            #nav::item { padding: 9px 12px; }
            #stat { border: 1px solid palette(mid); border-radius: 8px; padding: 6px; }
        """)

        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(shield_icon(GREEN), self)
            menu = QMenu()
            self.tray_status = QAction("…")
            self.tray_status.setEnabled(False)
            menu.addAction(self.tray_status)
            menu.addSeparator()
            menu.addAction("Open Sentinel", self.show_window)
            menu.addAction("Quit", QApplication.quit)
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self.tray_clicked)
            self.tray.show()

        self.refresh()
        timer = QTimer(self)
        timer.timeout.connect(self.refresh)
        timer.start(3000)

    # --- state ---

    def unseen_alarms(self):
        """New ransomware alarms and break-in attempts, oldest first."""
        seen = float(self.settings.value("seen_until", 0))
        new = [e for e in self.events if not e.get("test") and e["time"] > seen]
        for a in self.attacks:
            if not a.get("test") and a["time"] > seen:
                new.append({"time": a["time"], "reason": f"{a['attack']} from {a['ip']}",
                            "actions": [a["detail"], a["info"]["label"],
                                        STATUS_TEXT[a["status"]]]})
        return sorted(new, key=lambda e: e["time"])

    def mark_seen(self):
        latest = [e["time"] for e in self.events] + [a["time"] for a in self.attacks]
        if latest:
            self.settings.setValue("seen_until", max(latest))
        self.refresh()

    def go(self, page_name):
        self.nav.setCurrentRow([name for name, _ in self.PAGES].index(page_name))

    def refresh(self):
        self.state = service_state()
        self.events = read_events()
        self.attacks = breakin.read_attacks()
        self.cfg = config.load_raw()

        new_attacks = [a for a in self.attacks[self.known_attacks:] if not a.get("test")]
        self.known_attacks = len(self.attacks)
        if new_attacks and self.tray:
            a = new_attacks[-1]
            self.tray.showMessage("Sentinel: break-in attempt",
                                  f"{a['attack']} from {a['ip']}\n{a['info']['label']}",
                                  shield_icon(RED), 15000)

        # Tell the user about brand-new alarms even when the window is hidden.
        new = [e for e in self.events[self.known_alarms:] if not e.get("test")]
        self.known_alarms = len(self.events)
        if new and self.tray:
            self.tray.showMessage("Sentinel: ransomware stopped", new[-1]["reason"],
                                  shield_icon(RED), 15000)

        if self.state != "active":
            color, status = ORANGE, "Protection is off"
        elif self.unseen_alarms():
            color, status = RED, "New alarm, click to see"
        else:
            color, status = GREEN, "You are protected"
        if self.tray:
            self.tray.setIcon(shield_icon(color))
            self.tray.setToolTip(f"Sentinel: {status}")
            self.tray_status.setText(status)
        self.setWindowIcon(shield_icon(color))
        self.pages[self.stack.currentIndex()].refresh()

    # --- actions ---

    def run_root(self, args, success_msg, after=None):
        def done(ok, output, cancelled):
            if after:
                after()
            if cancelled:
                pass
            elif ok:
                self.statusBar().showMessage(success_msg, 6000)
            else:
                QMessageBox.warning(self, "Sentinel", output or "Something went wrong.")
            self.refresh()
        self.tasks.append(RootTask(self, args, done))

    def run_tool_action(self, action):
        argv = (["pkexec"] + action["argv"]) if action.get("root") else action["argv"]
        proc = QProcess(self)
        proc.finished.connect(lambda *a: self.refresh())
        proc.start(argv[0], argv[1:])
        self.tasks.append(proc)

    def start_service(self):
        if config.INSTALLED:
            proc = QProcess(self)
            proc.finished.connect(lambda *a: self.refresh())
            proc.start("pkexec", ["systemctl", "enable", "--now", "sentinel"])
            self.tasks.append(proc)

    # --- window / tray ---

    def tray_clicked(self, reason):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if self.isVisible() and not self.isMinimized():
                self.hide()
            else:
                self.show_window()

    def show_window(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()
        self.refresh()

    def closeEvent(self, event):
        if self.tray:  # keep running in the tray
            event.ignore()
            self.hide()
        else:
            event.accept()


def run_gui():
    app = QApplication(sys.argv)
    app.setApplicationName("Sentinel")
    app.setDesktopFileName("sentinel")
    app.setQuitOnLastWindowClosed(False)
    win = MainWindow()
    if "--tray" not in sys.argv or not win.tray:
        win.show()
    sys.exit(app.exec())
