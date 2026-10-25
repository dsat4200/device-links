import json
import os
from pathlib import Path
import select
import subprocess
import sys
import unittest
from unittest.mock import patch

from PySide6.QtDBus import QDBusInterface, QDBusConnection
from PySide6.QtWidgets import QMessageBox

from device_links.backend import Backend
from device_links.dbus import BASE, DBusError, Object, call
from test_backend import BackendFixture
from test_model import document

SERVICE = "org.amber.DeviceLinks.Fixture"
ID = "fixturepeer"
PATH = f"{BASE}/devices/{ID}"


@unittest.skipUnless(os.environ.get("DBUS_SESSION_BUS_ADDRESS"), "run tests inside dbus-run-session")
class PairingTests(BackendFixture, unittest.TestCase):
    def setUp(self):
        super().setUp()
        env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1]) + os.pathsep + os.environ.get("PYTHONPATH", ""))
        self.fixture = subprocess.Popen([sys.executable, str(Path(__file__).with_name("dbus_fixture.py"))],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        self.addCleanup(self.stop_fixture)
        self.assertTrue(select.select([self.fixture.stdout], [], [], 5)[0], "D-Bus fixture did not start")
        ready = self.fixture.stdout.readline().strip()
        self.assertEqual(ready, "READY", self.fixture.stderr.read() if self.fixture.poll() is not None else "fixture not ready")
        self.control = Object("/fixture", "org.amber.DeviceLinks.Fixture", SERVICE)
        self.patchers = [
            patch.object(self.backend, "daemon", side_effect=lambda: Object(BASE, "org.kde.kdeconnect.daemon", SERVICE)),
            patch.object(self.backend, "device", side_effect=lambda key: Object(f"{BASE}/devices/{key}", "org.kde.kdeconnect.device", SERVICE)),
            patch.object(self.backend, "plugin", side_effect=lambda key: Object(f"{BASE}/devices/{key}/devicelinks", "org.kde.kdeconnect.device.devicelinks", SERVICE)),
            patch.object(self.backend, "local_document", return_value=document() | {"hostname": "self"}),
            patch.object(self.backend, "test_ssh"),
            patch.object(self.backend, "problem"),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def stop_fixture(self):
        self.fixture.terminate()
        try:
            self.fixture.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.fixture.kill()
            self.fixture.wait()
        self.fixture.stdout.close()
        self.fixture.stderr.close()

    def transition(self, stage):
        call(self.control, "transition", stage)

    def tick(self):
        Backend.tick(self.backend)

    def calls(self):
        return json.loads(call(self.control, "calls"))

    def approved(self):
        self.backend.state.approve(ID, "fixture-certificate", "other")

    def test_pairing_transition_waits_for_plugin_then_recovers(self):
        self.tick()
        self.assertTrue(self.backend.rows()[0]["reachable"])
        with patch("device_links.backend.QMessageBox.question", return_value=QMessageBox.Yes):
            self.backend.approve_pairing(ID)
        self.assertIn("requestPairing", self.calls())
        self.assertTrue(self.backend.state.peers[ID]["approved"])
        self.transition("paired")
        self.tick()
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-plugin")
        self.assertEqual(self.backend.state.linked(), {})

        self.transition("announced")
        # Reproduce Qt's misleading readiness check: interface valid, missing object.
        proxy = QDBusInterface(SERVICE, PATH + "/devicelinks", "org.kde.kdeconnect.device.devicelinks", QDBusConnection.sessionBus())
        self.assertTrue(proxy.isValid())
        self.tick()
        self.assertIsNone(self.backend.scan_error)
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-plugin")
        error = self.backend.diagnostics()["lastOperationError"]["error"]
        self.assertEqual(error["errorName"], "org.freedesktop.DBus.Error.UnknownObject")
        self.assertEqual(error["method"], "publish")
        self.assertEqual(error["path"], PATH + "/devicelinks")
        self.assertTrue(self.backend.state.peers[ID]["approved"])

        self.transition("complete")
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])
        self.assertEqual(self.backend.state.linked()[ID], document())
        self.backend.test_ssh.assert_called_once_with(ID, quiet=True)
        self.assertFalse(self.backend.problem.called)
        self.assertEqual(len(list(self.backend.remmina.glob("*.remmina"))), 2)

    def test_plugin_disappearing_mid_exchange_preserves_approval(self):
        self.approved()
        self.transition("ready")
        self.tick()
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-plugin")
        self.assertEqual(self.backend.diagnostics()["lastOperationError"]["error"]["method"], "remoteDocument")
        self.assertEqual(self.backend.state.linked(), {})
        self.transition("complete")
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])

    def test_discovery_is_not_authorization(self):
        self.transition("complete")
        self.tick()
        self.assertEqual(self.backend.state.linked(), {})
        self.assertNotIn("publish", self.calls())
        self.backend.test_ssh.assert_not_called()

    def test_disappearing_device_does_not_erase_trusted_keys(self):
        self.approved()
        self.transition("complete")
        self.tick()
        grants = (self.backend.state.root / "authorized_keys").read_text()
        self.transition("gone")
        self.tick()
        self.assertIsNone(self.backend.scan_error)
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-device")
        self.assertEqual((self.backend.state.root / "authorized_keys").read_text(), grants)
        self.transition("complete")
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])

    def test_incoming_pair_approval_waits_for_plugin_registration(self):
        self.transition("incoming")
        with patch("device_links.backend.QMessageBox.question", return_value=QMessageBox.Yes):
            self.backend.approve_pairing(ID, incoming=True)
        self.assertIn("acceptPairing", self.calls())
        self.tick()
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-plugin")
        self.transition("complete")
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])

    def test_cancel_never_grants_access(self):
        with patch("device_links.backend.QMessageBox.question", return_value=QMessageBox.No):
            self.backend.approve_pairing(ID)
        self.assertIn("cancelPairing", self.calls())
        self.assertEqual(self.backend.state.peers, {})
        self.assertEqual(self.backend.state.linked(), {})

    def test_expired_request_does_not_become_approved(self):
        def expire(*_args):
            self.transition("discovered")
            return QMessageBox.Yes
        with patch("device_links.backend.QMessageBox.question", side_effect=expire):
            self.backend.approve_pairing(ID)
        self.assertEqual(self.backend.state.peers, {})
        self.backend.problem.assert_called_once()
        self.assertIn("expired", self.backend.problem.call_args.args[0])

    def test_code_changed_while_dialog_open_requires_fresh_approval(self):
        def replace_request(*_args):
            call(self.control, "setCode", "DEADBEEF")
            return QMessageBox.Yes
        with patch("device_links.backend.QMessageBox.question", side_effect=replace_request):
            self.backend.approve_pairing(ID)
        self.assertEqual(self.backend.state.peers, {})
        self.backend.problem.assert_called_once()
        self.assertIn("changed", self.backend.problem.call_args.args[0])

    def test_direct_call_reports_object_and_operation(self):
        with self.assertRaises(DBusError) as caught:
            call(self.backend.plugin(ID), "remoteDocument")
        self.assertEqual(caught.exception.details["method"], "remoteDocument")
        self.assertEqual(caught.exception.details["path"], PATH + "/devicelinks")
        self.assertNotIn("arguments", caught.exception.details)

    def test_repeat_missing_object_does_not_flood_diagnostics(self):
        self.approved()
        self.transition("announced")
        self.tick()
        count = len(self.backend.recent_events)
        self.tick()
        self.tick()
        self.assertEqual(len(self.backend.recent_events), count)
        self.assertTrue(self.backend.state.peers[ID]["approved"])

    def test_polling_during_local_dialog_never_installs_keys(self):
        def accept_after_poll(*_args):
            self.transition("complete")
            self.tick()
            self.assertEqual(self.backend.state.linked(), {})
            self.assertNotIn("publish", self.calls())
            return QMessageBox.Yes
        with patch("device_links.backend.QMessageBox.question", side_effect=accept_after_poll):
            self.backend.approve_pairing(ID)
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])


if __name__ == "__main__":
    unittest.main()
