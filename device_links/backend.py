"""Session GUI/backend. Local IPC is same-user only; network commands use SSH."""
import base64
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from collections import deque

from PySide6.QtCore import QObject, QProcess, QTimer
from PySide6.QtNetwork import QLocalServer
from PySide6.QtWidgets import (QApplication, QCheckBox, QDialog, QDialogButtonBox,
                              QLabel, QLineEdit, QMessageBox, QVBoxLayout)

from . import VERSION
from .client import runtime
from .dbus import BASE, PLUGIN, UNAVAILABLE, NOT_READY, DBusError, call, interface
from .model import DEVICE_ID, State, atomic, descriptor, remmina_profiles, profile_path
from .pairing import PairingDialog, PairingSessionEnded
from .transport import REMOTE_WORKER, remote_command, ssh_args

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
        self.queued_pairings = set()
        self.active_pairing_dialog = None
        self.offered_transport_approval = set()
        self._closing = False
        self.window = None
        self.key_error = None
        self.scan_error = None
        self.phases = {}
        self.peer_errors = {}
        self.recent_events = deque(maxlen=30)
        self.last_operation_error = None
        self._ticking = False
        self.checked = set()
        self.ssh_inflight = set()
        self.ssh_verified = set()
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

    def phase(self, device_id, name, detail):
        old = self.phases.get(device_id)
        if old and old["name"] == name and old["detail"] == detail:
            return
        self.phases[device_id] = {"name": name, "detail": detail}
        self.record_event(device_id, name)

    def record_event(self, device_id, operation, error=None):
        # No arguments, key material, passwords, verification codes or command
        # output. Report the failing D-Bus operation, not just its raw message.
        details = error.details if isinstance(error, DBusError) else ({"message": str(error)[:1024]} if error else None)
        record = {"time": int(time.time()), "device": device_id, "operation": operation}
        if details:
            record["error"] = details
            self.last_operation_error = record
            self.peer_errors[device_id] = record
        if self.recent_events:
            previous = self.recent_events[-1]
            if {k: v for k, v in previous.items() if k != "time"} == {k: v for k, v in record.items() if k != "time"}:
                return
        self.recent_events.append(record)
        print("device-links: " + json.dumps(record), file=sys.stderr, flush=True)

    def sync_peer(self, device_id, peer, device):
        record = self.state.peers.get(device_id)
        # A modal verification dialog processes timers. Do not install keys,
        # erase a pending approval, or open another dialog while it is active.
        if device_id in self.pairing_dialogs:
            return
        if not peer["paired"]:
            if peer["incoming"]:
                self.phase(device_id, "approval-requested", "Compare the code and approve on both devices.")
                if not self.pairing_dialogs and device_id not in self.queued_pairings:
                    self.queued_pairings.add(device_id)
                    QTimer.singleShot(0, lambda key=device_id: self.open_incoming_pairing(key))
            elif peer["requested"]:
                self.phase(device_id, "waiting-peer", "Waiting for approval on the other device.")
            else:
                if record:
                    # The peer may finish pairing between the state snapshot
                    # and this branch. Never revoke on a mixed/stale snapshot.
                    if call(device, "pairStateAsInt") != 0:
                        return
                    had_access = bool(record.get("descriptor"))
                    self.forget(device_id, notify=False)
                    detail = ("Peer unpaired; app-managed access removed." if had_access else
                              "Pairing expired or was declined. Click Link and approve both screens within 30 seconds.")
                    self.problems[device_id] = detail
                    self.phase(device_id, "not-linked", detail)
                else:
                    self.phase(device_id, "not-linked", "Click Link to request approval.")
            return
        if not record:
            self.phase(device_id, "approval-required", "Paired by KDE Connect; click Link to approve SSH access here.")
            # A recipient may click KDE Connect's own notification before our
            # next poll sees RequestedByPeer. Native pairing is not SSH consent:
            # still show our real code-comparison dialog, once, automatically.
            if (peer["reachable"] and device_id not in self.offered_transport_approval
                    and device_id not in self.queued_pairings and not self.pairing_dialogs):
                self.offered_transport_approval.add(device_id)
                self.queued_pairings.add(device_id)
                QTimer.singleShot(0, lambda key=device_id: self.open_incoming_pairing(key))
            return
        if record["certificate"] != peer["certificate"]:
            raise ValueError("Peer certificate changed. Unlink and verify the actual device before linking again.")
        if not record.get("descriptor"):
            expected = self.pairing_token(peer["hostname"], call(device, "verificationKey"), peer["certificate"])
            if record.get("requestToken") != expected:
                # Human consent for an unfinished request is not transferable
                # to a later request, even when the device certificate is the same.
                self.forget(device_id, notify=False)
                detail = "The previous approval belongs to a different or interrupted request. Compare a fresh code before linking."
                self.problems[device_id] = detail
                self.phase(device_id, "approval-required", detail)
                return
        if not peer["reachable"]:
            self.phase(device_id, "offline", "Trusted peer is offline; existing approval is preserved.")
            return
        if self.key_error:
            self.phase(device_id, "identity-locked", "Unlock this device's identity before exchanging SSH keys.")
            return

        # Paired and reachable does not imply the dynamically registered plugin
        # object is ready. isValid() is explicitly NOT a readiness check.
        if PLUGIN not in (call(device, "loadedPlugins") or []):
            supported = device.property("supportedPlugins") or []
            if PLUGIN not in supported:
                self.problems[device_id] = "Peer does not advertise Device Links; pull, rebuild and open it there."
                self.phase(device_id, "integration-missing", self.problems[device_id])
            else:
                self.phase(device_id, "waiting-plugin", "Pairing approved; waiting for the identity plugin to load.")
            return
        try:
            plugin = self.plugin(device_id)
            if not call(plugin, "publish", json.dumps(self.local_document())):
                self.phase(device_id, "waiting-peer", "Waiting for the peer's encrypted link; retrying automatically.")
                return
            document = call(plugin, "remoteDocument")
        except DBusError as exc:
            if exc.name not in NOT_READY:
                raise
            self.phase(device_id, "waiting-plugin", "Identity plugin is not registered yet; retrying automatically.")
            self.record_event(device_id, "identity-plugin-not-ready", exc)
            return
        if not document:
            self.phase(device_id, "waiting-peer-identity", "Waiting for the other app's approval and SSH identity. Open Device Links there.")
            return
        clean = descriptor(json.loads(document), self.roster)
        if record.get("descriptor") != clean:
            self.phase(device_id, "exchanging", "Exchanging verified public SSH identities.")
            self.state.receive(device_id, peer["certificate"], clean)
            self.reconcile_profiles()
            self.checked.discard(device_id)
        self.peer_errors.pop(device_id, None)
        if device_id not in self.checked:
            self.checked.add(device_id)
            self.phase(device_id, "checking-ssh", "Public identities exchanged; testing SSH.")
            self.test_ssh(device_id, quiet=True)
        elif device_id in self.ssh_verified and not self.problems.get(device_id):
            self.phase(device_id, "linked", "SSH identities exchanged and connection checked.")

    def tick(self):
        if self._ticking or self._closing:
            return
        self._ticking = True
        try:
            daemon = self.daemon()
            ids = call(daemon, "devices", False, False) or []
            call(daemon, "setAnnouncedName", self.host)
            peers = {}
            for device_id in ids:
                try:
                    if not isinstance(device_id, str) or not DEVICE_ID.fullmatch(device_id):
                        raise ValueError("Discovery returned an invalid device identity")
                    device = self.device(device_id)
                    name = device.property("name")
                    if name not in self.roster or name == self.host:
                        continue
                    pair_state = call(device, "pairStateAsInt")
                    if pair_state not in (0, 1, 2, 3):
                        raise ValueError("Discovery returned an unknown pairing state")
                    peer = {"id": device_id, "hostname": name,
                            "reachable": bool(device.property("isReachable")),
                            "paired": pair_state == 3,
                            "requested": pair_state == 1,
                            "incoming": pair_state == 2,
                            "certificate": call(device, "encryptionInfo")}
                    peers[device_id] = peer
                    self.sync_peer(device_id, peer, device)
                except Exception as exc:
                    # One stale/disappearing object must not abort every peer's
                    # scan or be mistaken for rejection of an approved identity.
                    previous = self.peers.get(device_id)
                    if device_id not in peers and previous:
                        peers[device_id] = previous | {"reachable": False}
                    if isinstance(exc, DBusError) and exc.name in NOT_READY:
                        self.phase(device_id, "waiting-device", "Device service is changing; retrying automatically.")
                    else:
                        self.problems[device_id] = str(exc)
                        self.phase(device_id, "error", str(exc))
                    self.record_event(device_id, "poll-peer", exc)
            self.peers = peers
            self.scan_error = None
        except DBusError as exc:
            self.scan_error = "Discovery service unavailable; retrying automatically."
            self.record_event(None, "poll-discovery", exc)
            if exc.name in UNAVAILABLE and self.kde_process is None:
                self.kde_process = QProcess(self)
                self.kde_process.setProcessChannelMode(QProcess.ForwardedChannels)
                self.kde_process.finished.connect(lambda *_: setattr(self, "kde_process", None))
                self.kde_process.start(os.environ["DEVICE_LINKS_KDECONNECT"], [])
        except Exception as exc:
            self.scan_error = str(exc)
            self.record_event(None, "poll-discovery", exc)
        finally:
            self._ticking = False
        if self.window:
            self.window.refresh()

    def scan(self):
        call(self.daemon(), "forceOnNetworkChange")
        self.checked.clear()
        self.tick()

    def approve_pairing(self, device_id, incoming=False):
        if self.pairing_dialogs:
            # Never nest consent dialogs or start a second request because a
            # button/queued callback fired while another consent is visible.
            if device_id in self.pairing_dialogs and self.active_pairing_dialog:
                self.active_pairing_dialog.present()
            return
        self.pairing_dialogs.add(device_id)
        try:
            device = self.device(device_id)
            if not device.property("isReachable"):
                raise ValueError("Device is not reachable. Use Rescan after both devices are online.")
            pair_state = call(device, "pairStateAsInt")
            if incoming and pair_state not in (2, 3):
                self.record_event(device_id, "incoming-request-no-longer-pending")
                return
            self.problems.pop(device_id, None)
            if pair_state == 0:
                # Only the idle side starts a request. In particular do not
                # restart an outgoing timestamp or implicitly accept incoming
                # pairing via KDE Connect's requestPairing() convenience path.
                call(device, "requestPairing")
                self.record_event(device_id, "pairing-request-started")
            elif pair_state in (1, 2):
                self.record_event(device_id, "pairing-request-reused")
            code = call(device, "verificationKey")
            name = device.property("name")
            certificate = call(device, "encryptionInfo")
            # Capture exactly the request and certificate shown to the human.
            # An expired/replaced request must never gain SSH authorization.
            self.check_pairing_request(device, name, code, certificate)
            if self.confirm_pairing(device_id, name, code, certificate):
                self.check_pairing_request(device, name, code, certificate)
                self.state.approve(device_id, certificate, name, self.pairing_token(name, code, certificate))
                if call(device, "pairStateAsInt") == 2:
                    call(device, "acceptPairing")
                self.phase(device_id, "waiting-peer", "Approved here; waiting for pairing and the identity plugin.")
                self.record_event(device_id, "local-approval")
            else:
                self.check_pairing_request(device, name, code, certificate)
                call(device, "cancelPairing")
                self.state.forget(device_id)
                self.record_event(device_id, "pairing-declined-locally")
        except PairingSessionEnded as exc:
            # Do not leave a stale code visible, show another modal error, or
            # cancel a replacement request using the previous dialog's answer.
            self.record_event(device_id, "pairing-dialog-expired-or-changed", exc)
            if device_id in self.state.peers and not self.state.peers[device_id].get("descriptor"):
                self.forget(device_id, notify=False)
            self.problems[device_id] = str(exc)
            self.phase(device_id, "not-linked", str(exc))
        except Exception as exc:
            self.record_event(device_id, "approve-pairing", exc)
            detail = ("The device's discovery object changed during pairing. Rescan and try Link again. "
                      "The exact D-Bus operation is in Troubleshoot / copy report."
                      if isinstance(exc, DBusError) and exc.name in NOT_READY else str(exc))
            self.problems[device_id] = detail
            self.problem(detail)
        finally:
            self.pairing_dialogs.discard(device_id)
            self.tick()

    def open_incoming_pairing(self, device_id):
        self.queued_pairings.discard(device_id)
        if not self._closing:
            self.approve_pairing(device_id, incoming=True)

    def check_pairing_request(self, device, name, code, certificate):
        if call(device, "pairStateAsInt") not in (1, 2, 3):
            raise PairingSessionEnded("Pairing expired or was declined. Start again from only one device and approve both screens within 30 seconds.")
        if not device.property("isReachable"):
            raise PairingSessionEnded("Peer disconnected. The old pairing dialog was closed; reconnect and start a fresh request.")
        if code != call(device, "verificationKey") or certificate != call(device, "encryptionInfo") or name != device.property("name"):
            raise PairingSessionEnded("Pairing identity or code changed. The old dialog was closed; compare a fresh request started on only one device.")

    @staticmethod
    def pairing_token(name, code, certificate):
        # Persist only a digest until metadata exchange completes; neither raw
        # codes nor this internal binding enter diagnostic reports or logs.
        return hashlib.sha256(json.dumps([name, code, certificate]).encode()).hexdigest()

    def confirm_pairing(self, device_id, name, code, certificate):
        device = self.device(device_id)
        dialog = PairingDialog(self.host, name, code,
                               lambda: self.check_pairing_request(device, name, code, certificate))
        dialog.presented.connect(lambda: self.record_event(device_id, "approval-dialog-visible"))
        self.active_pairing_dialog = dialog
        self.record_event(device_id, "approval-dialog-opening")
        try:
            # QDialog.exec opens a real standalone dialog even if the manager
            # has never been opened, was closed, or is minimized.
            result = dialog.run()
            return result
        finally:
            self.active_pairing_dialog = None
            dialog.close()
            dialog.deleteLater()

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
        self.ssh_verified.discard(device_id)
        self.phases.pop(device_id, None)
        self.peer_errors.pop(device_id, None)
        self.offered_transport_approval.discard(device_id)
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
                phase = self.phases.get(key, {})
                row["phase"] = phase.get("name", "offline" if not row["reachable"] else "not-linked")
                row["statusDetail"] = phase.get("detail")
                row["lastError"] = self.peer_errors.get(key)
                rows.append(row)
        return rows

    def resolve(self, target):
        matches = [(key, peer) for key, peer in self.state.linked().items() if target in (key, peer["hostname"])]
        if len(matches) != 1:
            raise ValueError("Device is not uniquely linked; open Device Links to pair it")
        return matches[0]

    def test_ssh(self, device_id, quiet=False):
        if device_id in self.ssh_inflight:
            return
        peer = self.state.linked()[device_id]
        args = ssh_args(peer, device_id, self.state.root, self.identity)
        proc = QProcess(self)
        self.jobs.append(proc)
        self.ssh_inflight.add(device_id)
        def done(code, _status):
            self.ssh_inflight.discard(device_id)
            output = bytes(proc.readAllStandardError()).decode(errors="replace").strip()
            # An unlink can happen while the harmless connection check runs.
            # Do not resurrect its status or display a stale success message.
            if device_id not in self.state.linked():
                self.jobs.remove(proc)
                proc.deleteLater()
                return
            if code:
                self.ssh_verified.discard(device_id)
                self.problems[device_id] = output or "SSH check failed"
                self.phase(device_id, "ssh-failed", "SSH check failed; see Troubleshoot for the connection error.")
            else:
                self.ssh_verified.add(device_id)
                self.problems.pop(device_id, None)
                self.phase(device_id, "linked", "SSH connection checked successfully.")
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

    def diagnostics(self):
        return {"schema": 1, "version": VERSION, "hostname": self.host, "devices": self.rows(),
                "identityProblem": self.key_error, "discoveryProblem": self.scan_error,
                "lastOperationError": self.last_operation_error, "recentEvents": list(self.recent_events),
                "approvalPromptVisible": bool(self.active_pairing_dialog and self.active_pairing_dialog.isVisible()),
                "services": {"backend": "device-links.service", "discovery": "kdeconnectd"}}

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
                response = self.diagnostics()
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
        self._closing = True
        self.timer.stop()
        if self.active_pairing_dialog:
            self.active_pairing_dialog.reject()
        for session in list(self.sudo.values()):
            session.process.closeWriteChannel()
            if not session.process.waitForFinished(2000):
                session.process.kill()
        self.identity.unlink(missing_ok=True)
        self.identity.with_suffix(".pub").unlink(missing_ok=True)
        self.server.close()
        if self.kde_process:
            self.kde_process.terminate()
