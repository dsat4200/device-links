import json
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from PySide6.QtDBus import QDBusInterface, QDBusConnection
from PySide6.QtCore import Qt, QTimer
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from device_links.backend import Backend
from device_links.dbus import BASE, DBusError, Object, call
from device_links.pairing import PAIRING_TITLE
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
        token = self.backend.pairing_token("other", "A1B2C3D4", "fixture-certificate")
        self.backend.state.approve(ID, "fixture-certificate", "other", token)

    def test_pairing_transition_waits_for_plugin_then_recovers(self):
        self.tick()
        self.assertTrue(self.backend.rows()[0]["reachable"])
        with patch.object(self.backend, "confirm_pairing", return_value=True):
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
        with patch.object(self.backend, "confirm_pairing", return_value=True):
            self.backend.approve_pairing(ID, incoming=True)
        self.assertIn("acceptPairing", self.calls())
        self.tick()
        self.assertEqual(self.backend.rows()[0]["phase"], "waiting-plugin")
        self.transition("complete")
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])

    def test_cancel_never_grants_access(self):
        with patch.object(self.backend, "confirm_pairing", return_value=False):
            self.backend.approve_pairing(ID)
        self.assertIn("cancelPairing", self.calls())
        self.assertEqual(self.backend.state.peers, {})
        self.assertEqual(self.backend.state.linked(), {})

    def test_expired_request_does_not_become_approved(self):
        def expire(*_args):
            self.transition("discovered")
            return True
        with patch.object(self.backend, "confirm_pairing", side_effect=expire):
            self.backend.approve_pairing(ID)
        self.assertEqual(self.backend.state.peers, {})
        self.backend.problem.assert_not_called()
        self.assertIn("expired", self.backend.problems[ID])

    def test_code_changed_while_dialog_open_requires_fresh_approval(self):
        def replace_request(*_args):
            call(self.control, "setCode", "DEADBEEF")
            return True
        with patch.object(self.backend, "confirm_pairing", side_effect=replace_request):
            self.backend.approve_pairing(ID)
        self.assertEqual(self.backend.state.peers, {})
        self.backend.problem.assert_not_called()
        self.assertIn("changed", self.backend.problems[ID])

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
            return True
        with patch.object(self.backend, "confirm_pairing", side_effect=accept_after_poll):
            self.backend.approve_pairing(ID)
        self.tick()
        self.assertTrue(self.backend.rows()[0]["linked"])

    def test_outgoing_pending_request_is_reused_not_restarted(self):
        self.transition("pending")
        with patch.object(self.backend, "confirm_pairing", return_value=True):
            self.backend.approve_pairing(ID)
        self.assertNotIn("requestPairing", self.calls())
        self.assertTrue(self.backend.state.peers[ID]["approved"])

    def test_incoming_request_is_not_implicitly_accepted_before_consent(self):
        self.transition("incoming")
        def decline(*_args):
            self.assertNotIn("requestPairing", self.calls())
            self.assertNotIn("acceptPairing", self.calls())
            return False
        # Simulates clicking a row whose incoming flag was stale.
        with patch.object(self.backend, "confirm_pairing", side_effect=decline):
            self.backend.approve_pairing(ID, incoming=False)
        self.assertNotIn("acceptPairing", self.calls())
        self.assertEqual(self.backend.state.peers, {})

    def test_stale_incoming_callback_cannot_start_a_new_request(self):
        with patch.object(self.backend, "confirm_pairing") as confirm:
            self.backend.open_incoming_pairing(ID)
        confirm.assert_not_called()
        self.assertNotIn("requestPairing", self.calls())

    def test_new_request_cannot_reuse_an_old_unfinished_approval(self):
        self.approved()
        call(self.control, "setCode", "DEADBEEF")
        self.transition("complete")
        self.tick()
        self.assertEqual(self.backend.state.peers, {})
        self.assertEqual(self.backend.state.linked(), {})
        self.assertNotIn("publish", self.calls())
        self.assertEqual(self.backend.rows()[0]["phase"], "approval-required")

    def exercise_real_dialog(self, action, incoming=True, stage="incoming"):
        """Drive the actual visible Qt dialog. Never mock its creation/exec."""
        observed = {}
        actor = QTimer()
        guard = QTimer()
        actor.setInterval(10)
        guard.setSingleShot(True)
        def act():
            dialog = self.backend.active_pairing_dialog
            if dialog is None or not dialog.isVisible():
                return
            actor.stop()
            observed["seen"] = True
            try:
                self.assertEqual(dialog.windowTitle(), PAIRING_TITLE)
                self.assertIsNone(dialog.parent())
                self.assertTrue(dialog.isModal())
                self.assertIs(QApplication.activeModalWidget(), dialog)
                self.assertEqual(dialog.code_label.text(), "A1B2C3D4")
                self.assertTrue(self.backend.diagnostics()["approvalPromptVisible"])
                self.assertEqual(self.backend.state.linked(), {})
                action(dialog)
            except Exception as exc:
                observed["error"] = exc
                dialog.reject()
        def abort():
            observed["timeout"] = True
            dialog = self.backend.active_pairing_dialog
            if dialog:
                dialog.reject()
        actor.timeout.connect(act)
        guard.timeout.connect(abort)
        actor.start()
        guard.start(4000)
        try:
            if incoming:
                self.transition(stage)
                # The ordinary scan must automatically schedule the recipient's
                # dialog. No Link/approval method is called on the recipient.
                self.tick()
            else:
                QTimer.singleShot(0, lambda: self.backend.approve_pairing(ID))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                self.app.processEvents()
                if (observed.get("seen") and not self.backend.pairing_dialogs) or observed.get("timeout"):
                    break
                time.sleep(0.005)
        finally:
            actor.stop()
            guard.stop()
        if "error" in observed:
            raise observed["error"]
        self.assertTrue(observed.get("seen"), "Incoming approval dialog was never visible")
        self.assertFalse(observed.get("timeout"), "Real approval dialog did not finish")
        self.assertIsNone(self.backend.active_pairing_dialog)
        self.assertFalse(self.backend.diagnostics()["approvalPromptVisible"])

    def test_incoming_dialog_automatically_shows_without_a_manager_window(self):
        self.assertIsNone(self.backend.window)
        self.exercise_real_dialog(lambda dialog: QTest.mouseClick(dialog.cancel_button, Qt.LeftButton))
        self.assertIsNone(self.backend.window)
        self.assertEqual(self.backend.state.peers, {})

    def test_incoming_dialog_is_not_hidden_by_a_minimized_manager(self):
        self.backend.show()
        self.backend.window.showMinimized()
        self.app.processEvents()
        def decline(dialog):
            self.assertTrue(self.backend.window.isMinimized())
            QTest.mouseClick(dialog.cancel_button, Qt.LeftButton)
        self.exercise_real_dialog(decline)
        self.assertEqual(self.backend.state.peers, {})

    def test_real_incoming_dialog_requires_a_click_before_approval(self):
        self.exercise_real_dialog(lambda dialog: QTest.mouseClick(dialog.accept_button, Qt.LeftButton))
        self.assertTrue(self.backend.state.peers[ID]["approved"])
        self.assertIn("acceptPairing", self.calls())
        self.assertEqual(self.backend.state.linked(), {})

    def test_native_notification_acceptance_still_shows_real_ssh_consent(self):
        self.exercise_real_dialog(lambda dialog: QTest.mouseClick(dialog.accept_button, Qt.LeftButton), stage="complete")
        self.assertTrue(self.backend.state.peers[ID]["approved"])
        self.assertNotIn("requestPairing", self.calls())
        self.assertEqual(self.backend.state.linked(), {})

    def test_expired_real_dialog_closes_without_cancelling_another_request(self):
        self.exercise_real_dialog(lambda _dialog: self.transition("discovered"))
        self.assertEqual(self.backend.state.peers, {})
        self.assertNotIn("cancelPairing", self.calls())
        self.assertIn("expired", self.backend.problems[ID])

    def test_replaced_real_code_closes_old_dialog_without_approval(self):
        self.exercise_real_dialog(lambda _dialog: call(self.control, "setCode", "DEADBEEF"))
        self.assertEqual(self.backend.state.peers, {})
        self.assertNotIn("cancelPairing", self.calls())
        self.assertIn("changed", self.backend.problems[ID])
        report = json.dumps(self.backend.diagnostics())
        self.assertNotIn("A1B2C3D4", report)
        self.assertNotIn("DEADBEEF", report)

    def test_second_link_click_reuses_the_visible_dialog(self):
        def click_again(dialog):
            self.backend.approve_pairing(ID)
            self.assertIs(self.backend.active_pairing_dialog, dialog)
            self.assertEqual(self.calls().count("requestPairing"), 1)
            QTest.mouseClick(dialog.cancel_button, Qt.LeftButton)
        self.exercise_real_dialog(click_again, incoming=False)
        self.assertEqual(self.backend.state.peers, {})


if __name__ == "__main__":
    unittest.main()
