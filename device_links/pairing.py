"""Visible, standalone consent dialog for one immutable pairing request."""
from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QLabel, QVBoxLayout

PAIRING_TITLE = "Device Links — Pairing Approval"


class PairingSessionEnded(RuntimeError):
    """The dialog's original request expired, changed or disappeared."""


class PairingDialog(QDialog):
    presented = Signal()

    def __init__(self, local_name, peer_name, code, check_request):
        # Never parent consent to a hidden/minimized manager window. Keeping
        # this as an independent top-level also gives Sway one precise security
        # dialog title to allow above fullscreen, not the entire application.
        super().__init__(None, Qt.Dialog | Qt.WindowStaysOnTopHint)
        self.setObjectName("device-links-pairing-approval")
        self.setWindowTitle(PAIRING_TITLE)
        self.setWindowModality(Qt.ApplicationModal)
        self.failure = None
        self.check_request = check_request
        layout = QVBoxLayout(self)
        self.message = QLabel(
            f"Link {local_name} ↔ {peer_name}?\n\n"
            "Compare the code on BOTH devices. Only continue if they match.\n"
            "This grants SSH access to your account in both directions.")
        self.message.setTextFormat(Qt.PlainText)
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.code_label = QLabel(code)
        self.code_label.setTextFormat(Qt.PlainText)
        self.code_label.setAlignment(Qt.AlignCenter)
        font = self.code_label.font()
        font.setPointSize(font.pointSize() + 8)
        font.setBold(True)
        self.code_label.setFont(font)
        layout.addWidget(self.code_label)
        hint = QLabel("Click Link on only ONE device. Approve the incoming dialog on the other.\n"
                      "The request expires after 30 seconds; expired or changed codes close automatically.")
        hint.setTextFormat(Qt.PlainText)
        hint.setWordWrap(True)
        layout.addWidget(hint)
        buttons = QDialogButtonBox()
        self.accept_button = buttons.addButton("Codes match — Link", QDialogButtonBox.AcceptRole)
        self.cancel_button = buttons.addButton(QDialogButtonBox.Cancel)
        self.accept_button.setAutoDefault(False)
        self.cancel_button.setDefault(True)
        buttons.accepted.connect(self.checked_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.watchdog = QTimer(self)
        self.watchdog.setInterval(500)
        self.watchdog.timeout.connect(self.check)
        self.finished.connect(self.watchdog.stop)

    def present(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()
        if self.windowHandle():
            self.windowHandle().requestActivate()

    def showEvent(self, event):
        super().showEvent(event)
        self.presented.emit()

    def check(self):
        try:
            self.check_request()
        except Exception as exc:
            self.failure = str(exc)
            self.accept_button.setEnabled(False)
            self.reject()
            return False
        return True

    def checked_accept(self):
        if self.check():
            self.accept()

    def run(self):
        if not self.check():
            return False
        self.present()
        self.watchdog.start()
        accepted = self.exec() == QDialog.Accepted
        if self.failure:
            raise PairingSessionEnded(self.failure)
        return accepted
