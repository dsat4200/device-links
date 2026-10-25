"""Session GUI/backend. Local IPC is same-user only; network commands use SSH."""
import base64
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

from PySide6.QtCore import QObject, QProcess, QTimer
from PySide6.QtDBus import QDBusConnection, QDBusInterface, QDBusMessage
from PySide6.QtNetwork import QLocalServer
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QDialogButtonBox,
                              QLabel, QLineEdit, QMessageBox, QVBoxLayout)

from . import VERSION
from .client import runtime
from .model import State, atomic, descriptor, remmina_profiles, profile_path
from .transport import REMOTE_WORKER, remote_command, ssh_args

SERVICE = "org.kde.kdeconnect"
BASE = "/modules/kdeconnect"


def interface(path, name):
    return QDBusInterface(SERVICE, path, name, QDBusConnection.sessionBus())


def call(obj, method, *args):
    reply = obj.call(method, *args)
    if reply.type() == QDBusMessage.ErrorMessage:
        raise RuntimeError(reply.errorMessage())
    arguments = reply.arguments()
    return arguments[0] if arguments else None


class SudoConnection(QObject):
    def __init__(self, backend, device_id):
        super().__init__(backend)
        self.backend = backend
        self.device_id = device_id
        self.client = None
        self.request = None
        self.remember = False
        self.buffer = b""
        self.error = b""
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self.output)
        self.process.readyReadStandardError.connect(self.stderr)
        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.failed)
        peer = backend.state.linked()[device_id]
        args = ssh_args(peer, device_id, backend.state.root, backend.identity)
        self.process.start(args[0], [*args[1:], f"{REMOTE_WORKER} _sudo-worker"])
        # Authentication tickets are not kept past an idle connection lifetime.
        self.idle = QTimer(self)
        self.idle.setSingleShot(True)
        self.idle.timeout.connect(self.close)

    def run(self, client, request):
        if self.client:
            raise RuntimeError("Another administrator command is already running on this device")
        remote_command(request.get("argv"))
        self.idle.stop()
        self.client, self.request = client, request
        client.disconnected.connect(self.disconnected)
        self.write({"argv": request["argv"], "remember": self.remember})

    def write(self, message):
        self.process.write((json.dumps(message) + "\n").encode())

    def stderr(self):
        self.error = (self.error + bytes(self.process.readAllStandardError()))[-4096:]

    def output(self):
        self.buffer += bytes(self.process.readAllStandardOutput())
        if len(self.buffer) > 262144:
            self.close()
            return
        while b"\n" in self.buffer:
            line, self.buffer = self.buffer.split(b"\n", 1)
            try:
                message = json.loads(line)
                if message["type"] == "auth":
                    answer = self.backend.password_dialog(self.device_id, self.request, message["attempt"])
                    self.write(answer)
                    answer.clear()
                elif message["type"] == "done":
                    self.remember = message.get("remember") is True
                    client, self.client = self.client, None
                    self.request = None
                    if client:
                        self.backend.send(client, message)
                    if self.remember:
                        self.idle.start(5 * 60 * 1000)
                    else:
                        self.close()
                elif message["type"] in ("stdout", "stderr") and self.client:
                    self.backend.send(self.client, message, close=False)
                else:
                    raise ValueError("Unexpected remote control message")
            except (ValueError, KeyError, TypeError):
                self.close()
                return

    def disconnected(self):
        if self.client and not self.client.isOpen():
            self.client = None
            self.close()

    def failed(self, _error):
        if self.process.state() == QProcess.NotRunning:
            self.finished(255)

    def finished(self, code, _status=None):
        self.stderr()
        client, self.client = self.client, None
        if client:
            self.backend.send(client, {"error": "SSH administrator connection ended: " + self.error.decode(errors="replace"), "code": code})
        if self.backend.sudo.get(self.device_id) is self:
            del self.backend.sudo[self.device_id]

    def close(self):
        self.idle.stop()
        # EOF lets the remote helper invalidate its own sudo ticket in finally.
        self.process.closeWriteChannel()
        QTimer.singleShot(1500, self.process.terminate)


class Backend(QObject):
    def __init__(self, app, config_path):
        super().__init__()
        self.app = app
        self.config = json.loads(Path(config_path).read_text())
        self.host = self.config["hostname"]
        self.roster = self.config["devices"]
        self.runtime = runtime()
        self.state = State(os.environ.get("DEVICE_LINKS_STATE", str(Path.home() / ".local/share/device-links")), self.roster)
        self.identity = self.runtime / "identity"
        self.remmina = Path(os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local/share"))) / "remmina"
        self.sudo = {}
        self.peers = {}
        self.problems = {}
        self.pairing_dialogs = set()
        self.window = None
        self.key_error = None
        self.scan_error = None
        self.checked = set()
        self.jobs = []
        self.kde_process = None
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        endpoint = str(self.runtime / "control.sock")
        if not self.server.listen(endpoint):
            # Do not remove a socket that belongs to a running instance.
            import socket as sockets
            probe = sockets.socket(sockets.AF_UNIX)
            try:
                probe.connect(endpoint)
                raise RuntimeError("Device Links is already running")
            except ConnectionRefusedError:
                QLocalServer.removeServer(endpoint)
            finally:
                probe.close()
            if not self.server.listen(endpoint):
                raise RuntimeError(self.server.errorString())
        self.server.newConnection.connect(self.accept)
        self.state.reconcile()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(3000)
        self.app.aboutToQuit.connect(self.shutdown)
        QTimer.singleShot(0, self.initialize)

    def initialize(self):
        try:
            self.ensure_key()
        except Exception as exc:
            self.key_error = "Could not unlock device identity: " + str(exc)
        self.reconcile_profiles()
        self.tick()

    def ensure_key(self):
        import keyring
        service, account = "org.amber.DeviceLinks", "ssh-identity"
        key = keyring.get_password(service, account)
        if key:
            if not key.startswith("-----BEGIN OPENSSH PRIVATE KEY-----"):
                raise ValueError("Invalid identity in login keyring")
            atomic(self.identity, key)
        else:
            # Plaintext identity exists only in the user's private runtime tmpfs.
            if self.identity.exists():
                raise ValueError("Unstored runtime identity exists; restart your login session")
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "device-links", "-f", str(self.identity)], check=True)
            try:
                keyring.set_password(service, account, self.identity.read_text())
            except Exception:
                self.identity.unlink(missing_ok=True)
                self.identity.with_suffix(".pub").unlink(missing_ok=True)
                raise
        public = subprocess.check_output(["ssh-keygen", "-y", "-f", str(self.identity)], text=True).strip()
        atomic(self.identity.with_suffix(".pub"), public + "\n")
        self.key_error = None

    def local_document(self):
        if self.key_error or not self.identity.exists():
            raise RuntimeError(self.key_error or "Identity is not unlocked")
        data = {"schema": 1, "hostname": self.host, "user": self.config["user"],
                "publicKey": self.identity.with_suffix(".pub").read_text().strip(),
                "hostKey": Path(self.config.get("hostKeyFile", "/etc/ssh/ssh_host_ed25519_key.pub")).read_text().strip(),
                "sshPort": self.config.get("sshPort", 22),
                "desktopEndpoints": self.config.get("desktopEndpoints", [])}
        return descriptor(data, self.roster)

    def daemon(self):
        return interface(BASE, "org.kde.kdeconnect.daemon")

    def device(self, device_id):
        return interface(f"{BASE}/devices/{device_id}", "org.kde.kdeconnect.device")

    def plugin(self, device_id):
        return interface(f"{BASE}/devices/{device_id}/devicelinks", "org.kde.kdeconnect.device.devicelinks")

    def tick(self):
        try:
            daemon = self.daemon()
            if not daemon.isValid():
                if self.kde_process is None:
                    self.kde_process = QProcess(self)
                    # Keep discovery diagnostics in the device-links user journal.
                    self.kde_process.finished.connect(lambda *_: setattr(self, "kde_process", None))
                    self.kde_process.start(os.environ["DEVICE_LINKS_KDECONNECT"], [])
                self.scan_error = "Waiting for discovery service"
                return
            call(daemon, "setAnnouncedName", self.host)
            ids = call(daemon, "devices", False, False) or []
            peers = {}
            for device_id in ids:
                device = self.device(device_id)
                name = device.property("name")
                if name not in self.roster or name == self.host:
                    continue
                certificate = call(device, "encryptionInfo")
                peer = {"id": device_id, "hostname": name,
                        "reachable": bool(device.property("isReachable")),
                        "paired": bool(device.property("isPaired")),
                        "requested": bool(device.property("isPairRequested")),
                        "incoming": bool(device.property("isPairRequestedByPeer")),
                        "certificate": certificate}
                peers[device_id] = peer
                if peer["incoming"] and device_id not in self.pairing_dialogs:
                    QTimer.singleShot(0, lambda key=device_id: self.approve_pairing(key, incoming=True))
                record = self.state.peers.get(device_id)
                if record and not peer["paired"] and not peer["requested"] and not peer["incoming"]:
                    self.forget(device_id, notify=False)
                if peer["paired"] and record and record["certificate"] == certificate:
                    plugin = self.plugin(device_id)
                    if peer["reachable"] and plugin.isValid() and not self.key_error:
                        call(plugin, "publish", json.dumps(self.local_document()))
                        document = call(plugin, "remoteDocument")
                        if document:
                            clean = json.loads(document)
                            if record.get("descriptor") != clean:
                                self.state.receive(device_id, certificate, clean)
                                self.reconcile_profiles()
                                self.checked.discard(device_id)
                            if device_id not in self.checked:
                                self.checked.add(device_id)
                                self.test_ssh(device_id, quiet=True)
                    elif peer["reachable"]:
                        self.problems[device_id] = "Peer needs the Device Links integration; pull and rebuild it"
            self.peers = peers
            self.scan_error = None
        except Exception as exc:
            self.scan_error = str(exc)
        if self.window:
            self.window.refresh()

    def scan(self):
        call(self.daemon(), "forceOnNetworkChange")
        self.checked.clear()
        self.tick()

    def approve_pairing(self, device_id, incoming=False):
        if device_id in self.pairing_dialogs:
            return
        self.pairing_dialogs.add(device_id)
        try:
            device = self.device(device_id)
            if not device.property("isReachable") and not incoming:
                raise ValueError("Device is not reachable. Use Rescan after both devices are online.")
            if not incoming and not device.property("isPaired"):
                call(device, "requestPairing")
            code = call(device, "verificationKey")
            name = device.property("name")
            result = QMessageBox.question(self.window, "Approve device link",
                f"Link {self.host} ↔ {name}?\n\nVerification: {code}\n\n"
                "Check that the same code appears on the other device.\n"
                "This grants SSH access to your account in both directions.\n"
                "Approve only devices you control.", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if result == QMessageBox.Yes:
                self.state.approve(device_id, call(device, "encryptionInfo"), device.property("name"))
                if device.property("isPairRequestedByPeer"):
                    call(device, "acceptPairing")
            else:
                call(device, "cancelPairing")
                self.state.forget(device_id)
        except Exception as exc:
            self.problem(str(exc))
        finally:
            self.pairing_dialogs.discard(device_id)
            self.tick()

    def reconcile_profiles(self):
        self.state.reconcile()
        # The system ssh_config includes this app-owned fragment. The private
        # identity path is runtime-only and is never put in a Nix source tree.
        self.state.ssh_config(self.identity)
        for device_id, peer in self.state.linked().items():
            remmina_profiles(self.remmina, device_id, peer, self.identity, self.state.root / "known_hosts")
        self.export_known_hosts()

    def export_known_hosts(self):
        # Remmina/libssh reads normal known_hosts; preserve all manually managed lines.
        path = Path.home() / ".ssh/known_hosts"
        begin, end = "# BEGIN DEVICE LINKS\n", "# END DEVICE LINKS\n"
        original = path.read_text() if path.exists() else ""
        if begin in original:
            before, remainder = original.split(begin, 1)
            if end not in remainder:
                raise ValueError("Incomplete Device Links known_hosts block; repair required")
            _, after = remainder.split(end, 1)
            original = before + after
        lines = "".join(f"{p['hostname']}.local,[{p['hostname']}.local]:{p['sshPort']} {p['hostKey']}\n"
                        for p in self.state.linked().values())
        content = original + ("\n" if original and not original.endswith("\n") else "") + begin + lines + end
        if not path.exists() or path.read_text() != content:
            atomic(path, content)

    def forget(self, device_id, notify=True):
        if device_id in self.sudo:
            self.sudo[device_id].close()
        self.state.forget(device_id)
        for protocol in ("SSH", "RDP", "VNC"):
            profile_path(self.remmina, device_id, protocol).unlink(missing_ok=True)
        self.problems.pop(device_id, None)
        self.checked.discard(device_id)
        self.reconcile_profiles()
        if notify:
            call(self.device(device_id), "unpair")

    def rows(self):
        rows = []
        linked = self.state.linked()
        for host in self.roster:
            if host == self.host:
                continue
            found = [p for p in self.peers.values() if p["hostname"] == host]
            discovered = {p["id"] for p in found}
            for key, value in self.state.peers.items():
                if key not in discovered and value.get("hostname") == host:
                    found.append({"id": key, "hostname": host,
                                  "reachable": False, "paired": bool(value.get("descriptor")),
                                  "requested": False, "incoming": False})
            if not found:
                found = [{"id": None, "hostname": host, "reachable": False, "paired": False}]
            for peer in found:
                row = {k: v for k, v in peer.items() if k != "certificate"}
                key = row["id"]
                row["linked"] = key in linked
                row["approved"] = key in self.state.peers
                row["desktopEndpoints"] = linked.get(key, {}).get("desktopEndpoints", [])
                row["problem"] = self.problems.get(key)
                rows.append(row)
        return rows

    def resolve(self, target):
        matches = [(key, peer) for key, peer in self.state.linked().items() if target in (key, peer["hostname"])]
        if len(matches) != 1:
            raise ValueError("Device is not uniquely linked; open Device Links to pair it")
        return matches[0]

    def test_ssh(self, device_id, quiet=False):
        peer = self.state.linked()[device_id]
        args = ssh_args(peer, device_id, self.state.root, self.identity)
        proc = QProcess(self)
        self.jobs.append(proc)
        def done(code, _status):
            output = bytes(proc.readAllStandardError()).decode(errors="replace").strip()
            if code:
                self.problems[device_id] = output or "SSH check failed"
            else:
                self.problems.pop(device_id, None)
            if not quiet:
                self.problem(output if code else "SSH works. No administrator changes were made.")
            self.jobs.remove(proc)
            proc.deleteLater()
            if self.window:
                self.window.refresh()
        proc.finished.connect(done)
        proc.start(args[0], [*args[1:], "true"])

    def password_dialog(self, device_id, request, attempt):
        if not request:
            return {"cancel": True}
        peer = self.state.linked()[device_id]
        dialog = QDialog(self.window)
        dialog.setWindowTitle(f"Administrator access on {peer['hostname']}")
        layout = QVBoxLayout(dialog)
        label = QLabel(f"Target: {peer['user']}@{peer['hostname']}\n\n"
                       f"Purpose: {request.get('purpose', '')}\n\nCommand: {remote_command(request['argv'])}\n\n"
                       + ("Incorrect password. " if attempt > 1 else "")
                       + "Enter the target device's password:")
        from PySide6.QtCore import Qt
        label.setTextFormat(Qt.PlainText)
        label.setWordWrap(True)
        layout.addWidget(label)
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        layout.addWidget(password)
        remember = QCheckBox("Remember for this connection (expires after inactivity)")
        layout.addWidget(remember)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        password.setFocus()
        accepted = dialog.exec() == QDialog.Accepted
        answer = {"password": password.text(), "remember": remember.isChecked()} if accepted else {"cancel": True}
        password.clear()
        dialog.deleteLater()
        return answer

    def show(self):
        if self.window is None:
            from .gui import Window
            self.window = Window(self)
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def problem(self, text):
        QMessageBox.information(self.window, "Device Links", text)

    def accept(self):
        while self.server.hasPendingConnections():
            client = self.server.nextPendingConnection()
            client.setProperty("buffer", b"")
            client.readyRead.connect(lambda c=client: self.request(c))
            client.disconnected.connect(client.deleteLater)

    def send(self, client, response, close=True):
        if client.isOpen():
            client.write((json.dumps(response) + "\n").encode())
            client.flush()
            if close:
                client.disconnectFromServer()

    def request(self, client):
        data = bytes(client.property("buffer") or b"") + bytes(client.readAll())
        if len(data) > 65536:
            self.send(client, {"error": "Request too large"})
            return
        if b"\n" not in data:
            client.setProperty("buffer", data)
            return
        try:
            request = json.loads(data.split(b"\n", 1)[0])
            op = request.get("op")
            if op == "show":
                self.show()
                response = {"ok": True}
            elif op in ("list", "scan", "doctor"):
                if op == "scan":
                    self.scan()
                response = {"schema": 1, "version": VERSION, "hostname": self.host, "devices": self.rows(),
                            "identityProblem": self.key_error, "discoveryProblem": self.scan_error,
                            "services": {"backend": "device-links.service", "discovery": "kdeconnectd"}}
            elif op == "resolve":
                key, peer = self.resolve(request["target"])
                response = {"id": key, "peer": peer, "state": str(self.state.root), "identity": str(self.identity)}
            elif op == "gsudo":
                key, _ = self.resolve(request["target"])
                remote_command(request.get("argv"))
                if not isinstance(request.get("purpose"), str) or len(request["purpose"]) > 4096:
                    raise ValueError("A short administrator purpose is required")
                if key not in self.sudo:
                    self.sudo[key] = SudoConnection(self, key)
                self.sudo[key].run(client, request)
                return
            else:
                raise ValueError("Unsupported operation; pairing approval is GUI-only")
            self.send(client, response)
        except Exception as exc:
            self.send(client, {"error": str(exc)})

    def shutdown(self):
        for session in list(self.sudo.values()):
            session.process.closeWriteChannel()
            if not session.process.waitForFinished(2000):
                session.process.kill()
        self.identity.unlink(missing_ok=True)
        self.identity.with_suffix(".pub").unlink(missing_ok=True)
        self.server.close()
        if self.kde_process:
            self.kde_process.terminate()
