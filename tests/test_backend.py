import concurrent.futures
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from PySide6.QtDBus import QDBusMessage
from PySide6.QtWidgets import QApplication

from device_links.backend import Backend
from device_links.client import rpc
from device_links.gui import Window
from test_model import document


class OfflineBackend(Backend):
    def initialize(self):
        pass

    def tick(self):
        pass


class BackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])
        cls.app.setQuitOnLastWindowClosed(False)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "runtime").mkdir(mode=0o700)
        config = self.root / "config.json"
        config.write_text(json.dumps({"hostname": "self", "devices": ["self", "other"], "user": "amber"}))
        self.env = patch.dict(os.environ, {"HOME": str(self.root), "XDG_RUNTIME_DIR": str(self.root / "runtime"),
                              "XDG_DATA_HOME": str(self.root / "data"), "DEVICE_LINKS_STATE": str(self.root / "state")})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.backend = OfflineBackend(self.app, config)
        self.addCleanup(self.close)

    def close(self):
        self.backend.timer.stop()
        self.backend.shutdown()
        if self.backend.window:
            self.backend.window.close()
        self.backend.deleteLater()
        self.app.processEvents()

    def request(self, message):
        with concurrent.futures.ThreadPoolExecutor(1) as pool:
            result = pool.submit(rpc, message, 3)
            deadline = time.monotonic() + 4
            while not result.done() and time.monotonic() < deadline:
                self.app.processEvents()
                time.sleep(0.005)
            return result.result(timeout=1)

    def test_local_ipc_and_offline_roster(self):
        status = self.request({"op": "list"})
        self.assertEqual(status["hostname"], "self")
        self.assertEqual(status["devices"][0]["hostname"], "other")
        self.assertFalse(status["devices"][0]["linked"])
        self.assertEqual((self.backend.runtime / "control.sock").stat().st_mode & 0o077, 0)
        with self.assertRaisesRegex(RuntimeError, "approval is GUI-only"):
            self.request({"op": "approve", "target": "other"})
        self.assertEqual(self.backend.state.peers, {})

    def test_keyring_identity_restores_without_changing_key(self):
        vault = {}
        with patch("keyring.get_password", side_effect=lambda s, a: vault.get((s, a))), \
             patch("keyring.set_password", side_effect=lambda s, a, v: vault.__setitem__((s, a), v)):
            self.backend.ensure_key()
            original = self.backend.identity.read_text()
            self.assertEqual(self.backend.identity.stat().st_mode & 0o777, 0o600)
            self.backend.identity.unlink()
            self.backend.ensure_key()
            self.assertEqual(original, self.backend.identity.read_text())
        for path in self.backend.state.root.iterdir():
            self.assertNotIn("PRIVATE KEY", path.read_text())

    def test_remmina_and_known_hosts_preserve_manual_configuration(self):
        ssh = self.root / ".ssh"
        ssh.mkdir()
        (ssh / "known_hosts").write_text("manual-host manual-key\n")
        self.backend.state.approve("one", "certificate")
        self.backend.state.receive("one", "certificate", document())
        self.backend.reconcile_profiles()
        self.backend.reconcile_profiles()
        known = (ssh / "known_hosts").read_text()
        self.assertEqual(known.count("# BEGIN DEVICE LINKS"), 1)
        self.assertIn("manual-host manual-key\n", known)
        self.assertIn("other.local", known)
        self.assertIn(str(self.backend.identity), (self.backend.state.root / "ssh_config").read_text())
        self.backend.forget("one", notify=False)
        self.assertNotIn("other.local", (ssh / "known_hosts").read_text())
        self.assertIn("manual-host", (ssh / "known_hosts").read_text())
        self.assertEqual(list(self.backend.remmina.glob("*.remmina")), [])

    def test_window_renders_offline_and_linked_rows(self):
        window = Window(self.backend)
        self.backend.window = window
        self.assertEqual(window.devices.count(), 1)
        window.devices.setCurrentRow(0)
        self.assertFalse(window.buttons["Link"].isEnabled())
        self.backend.state.approve("one", "certificate")
        self.backend.state.receive("one", "certificate", document())
        window.refresh()
        window.devices.setCurrentRow(0)
        self.assertTrue(window.buttons["Open in Remmina"].isEnabled())
        self.assertIn("RDP", window.details.text())

    def test_approved_but_unconfirmed_link_is_visible_and_revocable(self):
        self.backend.state.approve("one", "certificate", "other")
        window = Window(self.backend)
        self.backend.window = window
        window.devices.setCurrentRow(0)
        self.assertIn("waiting for peer approval", window.devices.currentItem().text())
        self.assertFalse(window.buttons["Link"].isEnabled())
        self.assertTrue(window.buttons["Unlink"].isEnabled())

    def test_dbus_error_enum_available(self):
        self.assertIsNotNone(QDBusMessage.ErrorMessage)


if __name__ == "__main__":
    unittest.main()
