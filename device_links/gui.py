import json
import subprocess
import sys

from PySide6.QtCore import QProcess, Qt
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QListWidget,
                              QListWidgetItem, QMainWindow, QMessageBox,
                              QPushButton, QTextEdit, QVBoxLayout, QWidget)

from .model import profile_path
from .transport import ssh_args


class Window(QMainWindow):
    def __init__(self, backend):
        super().__init__()
        self.backend = backend
        self.setWindowTitle("Device Links")
        self.resize(820, 520)
        container = QWidget()
        self.setCentralWidget(container)
        layout = QVBoxLayout(container)
        header = QHBoxLayout()
        title = QLabel(f"Device Links — {backend.host}")
        title.setTextFormat(Qt.PlainText)
        header.addWidget(title)
        header.addStretch()
        scan = QPushButton("Rescan")
        scan.clicked.connect(lambda: self.action(backend.scan))
        header.addWidget(scan)
        layout.addLayout(header)
        self.status = QLabel()
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.devices = QListWidget()
        self.devices.currentItemChanged.connect(self.selection)
        layout.addWidget(self.devices)
        self.details = QLabel()
        self.details.setTextFormat(Qt.PlainText)
        self.details.setWordWrap(True)
        layout.addWidget(self.details)
        buttons = QHBoxLayout()
        self.buttons = {}
        for label, callback in [("Link", self.link), ("Open in Remmina", self.remmina),
                                ("Open SSH", self.ssh), ("Test SSH", self.test),
                                ("Test administrator access", self.test_sudo), ("Unlink", self.unlink)]:
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, fn=callback: self.action(fn))
            buttons.addWidget(button)
            self.buttons[label] = button
        layout.addLayout(buttons)
        footer = QHBoxLayout()
        for label, callback in [("Troubleshoot / copy report", self.diagnostics),
                                ("Repair Remmina entries", backend.reconcile_profiles),
                                ("Unlock identity", self.unlock)]:
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, fn=callback: self.action(fn))
            footer.addWidget(button)
        layout.addLayout(footer)
        self.refresh()

    def action(self, fn):
        try:
            fn()
        except Exception as exc:
            self.backend.problem(str(exc))

    def selected(self):
        item = self.devices.currentItem()
        if not item:
            raise ValueError("Select a device first")
        return item.data(Qt.UserRole)

    def refresh(self):
        old = self.devices.currentItem()
        old_id = old.data(Qt.UserRole).get("id") if old else None
        self.devices.blockSignals(True)
        self.devices.clear()
        for row in self.backend.rows():
            status = "Online" if row["reachable"] else "Offline"
            linked = "Linked" if row["linked"] else "Not linked"
            if row.get("incoming"):
                linked = "Approval requested"
            elif row.get("requested"):
                linked = "Waiting for approval"
            elif row.get("approved") and not row["linked"]:
                linked = "Approved here · waiting for peer approval"
            if row.get("phase") == "waiting-plugin":
                linked = "Paired · preparing SSH link"
            elif row.get("phase") == "waiting-peer-identity":
                linked = "Paired · waiting for other app"
            elif row.get("phase") == "checking-ssh":
                linked = "Testing SSH"
            if row.get("problem"):
                linked += " · Connection problem"
            item = QListWidgetItem(f"{row['hostname']}     {status} · {linked}")
            item.setData(Qt.UserRole, row)
            self.devices.addItem(item)
            if row["id"] == old_id:
                self.devices.setCurrentItem(item)
        self.devices.blockSignals(False)
        issues = [v for v in (self.backend.key_error, self.backend.scan_error) if v]
        self.status.setText("\n".join(issues) if issues else "Discovery is active. Link only devices you control. Closing this window keeps discovery running.")
        self.selection()

    def selection(self, *_args):
        item = self.devices.currentItem()
        row = item.data(Qt.UserRole) if item else {}
        linked = row.get("linked", False)
        for label, button in self.buttons.items():
            button.setEnabled(linked)
        self.buttons["Link"].setEnabled(bool(row.get("id")) and row.get("reachable", False) and not linked
                                        and not row.get("approved") and not row.get("requested")
                                        and not self.backend.pairing_dialogs and not self.backend.key_error)
        self.buttons["Link"].setText("Approve request" if row.get("incoming") else "Link")
        self.buttons["Unlink"].setEnabled(bool(row.get("id")) and (linked or row.get("approved", False) or row.get("paired", False)))
        protocols = ", ".join(p["protocol"] for p in row.get("desktopEndpoints", []))
        self.details.setText(row.get("problem") or row.get("statusDetail") or (f"Remote desktop: {protocols}. Opens in Remmina." if protocols else
                             "Remote desktop: no endpoint reported. Remmina SSH is available after linking; desktop services are configured separately."))

    def link(self):
        row = self.selected()
        self.backend.approve_pairing(row["id"], incoming=row.get("incoming", False))

    def remmina(self):
        row = self.selected()
        self.backend.reconcile_profiles()
        protocols = [p["protocol"] for p in row["desktopEndpoints"]]
        protocol = protocols[0] if protocols else "SSH"
        path = profile_path(self.backend.remmina, row["id"], protocol)
        subprocess.Popen(["remmina", "--connect", str(path)], stdin=subprocess.DEVNULL)

    def ssh(self):
        row = self.selected()
        peer = self.backend.state.linked()[row["id"]]
        args = ssh_args(peer, row["id"], self.backend.state.root, self.backend.identity)
        args[1] = "-t"
        subprocess.Popen(["kitty", *args], stdin=subprocess.DEVNULL)

    def test(self):
        self.backend.test_ssh(self.selected()["id"])

    def test_sudo(self):
        row = self.selected()
        proc = QProcess(self)
        self.backend.jobs.append(proc)
        def done(code, _status):
            output = bytes(proc.readAllStandardOutput()).decode(errors="replace").strip()
            error = bytes(proc.readAllStandardError()).decode(errors="replace").strip()
            self.backend.problem("Administrator access works (uid 0). No system changes were made." if code == 0 and output == "0" else error or "Administrator test cancelled or failed.")
            self.backend.jobs.remove(proc)
            proc.deleteLater()
        proc.finished.connect(done)
        proc.start(sys.executable, ["-m", "device_links", "gsudo", row["hostname"], "Test administrator access (no changes)", "--", "id", "-u"])

    def unlink(self):
        row = self.selected()
        if QMessageBox.question(self, "Unlink device", f"Remove app-managed SSH access and Remmina entries for {row['hostname']}?\n\nExisting sessions and separately configured access are not revoked.",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            self.backend.forget(row["id"])
            self.refresh()

    def unlock(self):
        self.backend.ensure_key()
        self.backend.tick()

    def diagnostics(self):
        from PySide6.QtWidgets import QDialog, QDialogButtonBox
        report = self.backend.diagnostics() | {
                  "help": "device-links --help; journalctl --user -u device-links.service",
                  "checks": ["Both peers must have pulled and rebuilt the integration.",
                             "Initial pairing needs both devices logged in and the app running.",
                             "VPN policy or Wi-Fi client isolation can block LAN discovery/SSH.",
                             "Do not disable host-key checks or VPN kill switches to repair a link."]}
        dialog = QDialog(self)
        dialog.setWindowTitle("Device Links diagnostics")
        dialog.resize(700, 500)
        layout = QVBoxLayout(dialog)
        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(json.dumps(report, indent=2))
        layout.addWidget(text)
        copy = QPushButton("Copy report")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText()))
        layout.addWidget(copy)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()
