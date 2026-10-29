"""Sentinel window and tray icon (Qt, fits right into KDE).

The window runs as your normal user. It reads Sentinel's files directly and
asks for your password (through KDE's normal password dialog) only when it
has to change something: settings, quarantine, starting the service.
"""

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
    QAbstractItemView, QApplication, QCheckBox, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView,
    QInputDialog, QLabel, QListWidget, QListWidgetItem, QMainWindow, QMenu,
    QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QStackedWidget,
    QSystemTrayIcon, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import config, quarantine

GREEN, ORANGE, RED = QColor("#27ae60"), QColor("#f39c12"), QColor("#da4453")
SENTINEL_CMD = "/usr/local/bin/sentinel"


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
                ("folders", "Protected folders"), ("alarms", "Alarms (30 days)"),
                ("quarantine", "In quarantine"), ("last", "Last alarm")]):
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

        # Tests
        tests = QGroupBox("Try it out (safe)")
        row = QHBoxLayout(tests)
        test_btn = QPushButton(theme_icon("tools-check-spelling"), "Run ransomware test")
        test_btn.setToolTip("Releases harmless fake ransomware in a throwaway "
                            "folder and checks that Sentinel stops it.")
        test_btn.clicked.connect(win.run_ransomware_test)
        popup_btn = QPushButton(theme_icon("preferences-desktop-notification"), "Show test popup")
        popup_btn.clicked.connect(lambda: RootTask(self, ["test-popup"], lambda *a: None))
        row.addWidget(test_btn)
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
            sub = f"Sentinel is watching {len(folders)} folders for ransomware."
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
        self.stats["quarantine"].setText(str(len(quarantine.list_items())))
        self.stats["last"].setText(time_ago(real[-1]["time"]) if real else "never")

        def onoff(v):
            return "<b style='color:#27ae60'>On</b>" if v else "<b style='color:#da4453'>Off</b>"
        self.features.setText(
            f"Trap files: {onoff(cfg['canaries'])} &nbsp;&nbsp; "
            f"Stop ransomware automatically: {onoff(cfg['auto_kill'])} &nbsp;&nbsp; "
            f"Quarantine: {onoff(cfg['auto_quarantine'])}<br>"
            f"Alarm when {cfg['burst_files']} files change within "
            f"{cfg['window_seconds']} seconds and look encrypted.")

    def on_action(self):
        if self.win.state != "active":
            self.win.start_service()
        elif self.action.text() == "Open settings":
            self.win.nav.setCurrentRow(3)
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


class SettingsPage(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        layout = QVBoxLayout(self)
        layout.addWidget(heading("Settings"))

        group = QGroupBox("Protected folders")
        v = QVBoxLayout(group)
        self.folders = QListWidget()
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
        row = QHBoxLayout()
        self.burst = QSpinBox()
        self.burst.setRange(5, 1000)
        self.window = QSpinBox()
        self.window.setRange(1, 120)
        for w in (QLabel("Alarm when"), self.burst, QLabel("files change within"),
                  self.window, QLabel("seconds")):
            row.addWidget(w)
        row.addStretch()
        v.addLayout(row)
        v.addWidget(hint("Lower numbers react faster but can cause false alarms."))
        layout.addWidget(group)

        group = QGroupBox("Trusted programs (never stopped)")
        v = QVBoxLayout(group)
        self.allow = QListWidget()
        v.addWidget(self.allow)
        v.addLayout(self.list_buttons(self.allow, self.add_program))
        layout.addWidget(group, 1)

        row = QHBoxLayout()
        row.addStretch()
        undo = QPushButton(theme_icon("edit-undo"), "Undo changes")
        undo.clicked.connect(self.load)
        save = QPushButton(theme_icon("document-save"), "Save")
        save.setDefault(True)
        save.clicked.connect(self.save)
        row.addWidget(undo)
        row.addWidget(save)
        layout.addLayout(row)
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
        self.window.setValue(cfg["window_seconds"])
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
            "window_seconds": self.window.value(),
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
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Ransomware test")
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
        self.task = RootTask(self, ["test-ransomware"], self.done, self.out.insertPlainText)

    def done(self, ok, output, cancelled):
        if cancelled:
            self.status.setText("Cancelled.")
        elif ok:
            self.status.setText("✅ Test passed: Sentinel stopped the fake ransomware.")
        else:
            self.status.setText("❌ Test failed, see the output below.")
        self.parent().refresh()


# ---------- main window ----------

class MainWindow(QMainWindow):
    PAGES = [("Overview", "security-high"), ("Quarantine", "folder-locked"),
             ("Activity", "view-history"), ("Settings", "configure")]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel")
        self.setWindowIcon(shield_icon(GREEN))
        self.resize(900, 620)
        self.settings = QSettings("Sentinel", "Sentinel")
        self.state, self.events, self.cfg = "unknown", [], config.load_raw()
        self.tasks = []
        self.tray = None
        self.known_alarms = len(read_events())

        central = QWidget()
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFixedWidth(190)
        self.nav.setIconSize(QSize(22, 22))
        self.stack = QStackedWidget()
        self.pages = [OverviewPage(self), QuarantinePage(self), ActivityPage(self),
                      SettingsPage(self)]
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
        seen = float(self.settings.value("seen_until", 0))
        return [e for e in self.events if not e.get("test") and e["time"] > seen]

    def mark_seen(self):
        if self.events:
            self.settings.setValue("seen_until", self.events[-1]["time"])
        self.refresh()

    def refresh(self):
        self.state = service_state()
        self.events = read_events()
        self.cfg = config.load_raw()

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

    def start_service(self):
        if config.INSTALLED:
            proc = QProcess(self)
            proc.finished.connect(lambda *a: self.refresh())
            proc.start("pkexec", ["systemctl", "enable", "--now", "sentinel"])
            self.tasks.append(proc)

    def run_ransomware_test(self):
        TestDialog(self).show()

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
