import base64
import configparser
import json
import os
from pathlib import Path
import shlex
import tempfile
import unittest

from device_links.model import State, atomic, descriptor, profile_path, remmina_profiles, ssh_key
from device_links.transport import remote_command, ssh_args


def key(seed=1):
    return "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes([seed]) * 32).decode()


def document():
    return {"schema": 1, "hostname": "other", "user": "amber", "publicKey": key(),
            "hostKey": key(2), "sshPort": 22, "desktopEndpoints": [{"protocol": "RDP", "port": 3389}]}


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = State(self.root / "state", ["other", "third"])

    def test_unapproved_peer_cannot_install_keys(self):
        with self.assertRaises(ValueError):
            self.state.receive("peer-id", "certificate", document())
        self.assertFalse((self.state.root / "authorized_keys").exists())

    def test_pair_persistence_revoke_and_manual_keys(self):
        manual = self.root / ".ssh/authorized_keys"
        atomic(manual, "manual credential untouched\n")
        self.state.approve("peer-id", "certificate")
        self.state.receive("peer-id", "certificate", document())
        self.assertIn(key(), (self.state.root / "authorized_keys").read_text())
        self.assertIn(key(2), (self.state.root / "known_hosts").read_text())
        reopened = State(self.state.root, ["other"])
        self.assertEqual(reopened.linked()["peer-id"], document())
        reopened.forget("peer-id")
        self.assertEqual((self.state.root / "authorized_keys").read_text(), "")
        self.assertEqual(manual.read_text(), "manual credential untouched\n")

    def test_changed_certificate_or_keys_fail_closed(self):
        self.state.approve("peer-id", "certificate")
        self.state.receive("peer-id", "certificate", document())
        for certificate, data in [("impostor", document()), ("certificate", document() | {"publicKey": key(3)}),
                                  ("certificate", document() | {"hostKey": key(3)})]:
            with self.assertRaises(ValueError):
                self.state.receive("peer-id", certificate, data)
        self.assertEqual(self.state.linked()["peer-id"], document())

    def test_duplicate_name_cannot_replace_existing_identity(self):
        self.state.approve("one", "cert1")
        self.state.receive("one", "cert1", document())
        self.state.approve("two", "cert2")
        with self.assertRaises(ValueError):
            self.state.receive("two", "cert2", document())

    def test_approved_name_cannot_change_during_identity_exchange(self):
        self.state.approve("one", "cert1", "third")
        with self.assertRaisesRegex(ValueError, "hostname does not match"):
            self.state.receive("one", "cert1", document())
        self.assertEqual(self.state.linked(), {})

    def test_roster_is_not_trust_and_removed_host_loses_grant(self):
        self.state.approve("one", "cert1")
        with self.assertRaises(ValueError):
            self.state.receive("one", "cert1", document() | {"hostname": "unconfigured"})
        self.state.receive("one", "cert1", document())
        reopened = State(self.state.root, ["third"])
        reopened.reconcile()
        self.assertEqual((reopened.root / "authorized_keys").read_text(), "")

    def test_strict_schema(self):
        for change in [{"hostname": "other\nHost evil"}, {"user": "-oProxyCommand=evil"}, {"sshPort": True},
                       {"schema": 2}, {"publicKey": "ssh-ed25519 AAAA"},
                       {"desktopEndpoints": [{"protocol": "EXEC", "port": 22}]},
                       {"desktopEndpoints": [{"protocol": "VNC", "port": 70000}]}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                descriptor(document() | change, ["other"])
        with self.assertRaises(ValueError):
            ssh_key('command="evil" ' + key())

    def test_atomic_private_and_no_symlink(self):
        path = self.root / "private"
        atomic(path, "data")
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(ValueError):
            atomic(link, "overwrite")
        self.assertEqual(path.read_text(), "data")

    def test_remmina_merge_preserves_user_settings_and_other_profiles(self):
        directory = self.root / "remmina"
        directory.mkdir()
        manual = directory / "work.remmina"
        manual.write_text("personal work configuration")
        rdp = profile_path(directory, "one", "RDP")
        rdp.write_text("[remmina]\nname=old\nresolution_width=1920\nclipboard=0\npassword=.\n")
        for _ in range(2):
            paths = remmina_profiles(directory, "one", document(), self.root / "key", self.root / "known_hosts")
        config = configparser.ConfigParser()
        config.read(rdp)
        self.assertEqual(config["remmina"]["server"], "other.local:3389")
        self.assertEqual(config["remmina"]["resolution_width"], "1920")
        self.assertEqual(config["remmina"]["password"], ".")
        self.assertEqual(manual.read_text(), "personal work configuration")
        ssh = configparser.ConfigParser(interpolation=None)
        ssh.read(profile_path(directory, "one", "SSH"))
        self.assertEqual(ssh["remmina"]["ssh_auth"], "1")
        self.assertEqual(ssh["remmina"]["ssh_stricthostkeycheck"], "1")
        self.assertEqual(len(list(directory.glob("device-links-*"))), 2)
        self.assertEqual(len(paths), 2)

    def test_no_fake_desktop_profile(self):
        paths = remmina_profiles(self.root / "remmina", "one", document() | {"desktopEndpoints": []}, "identity", "known_hosts")
        self.assertEqual(len(paths), 1)
        self.assertTrue(paths[0].endswith("-ssh.remmina"))

    def test_remote_argv_roundtrip_no_shell_injection(self):
        argv = ["printf", "%s", "$(touch /never)", "a'b", "semi;colon", "line\nbreak"]
        self.assertEqual(shlex.split(remote_command(argv)), argv)
        with self.assertRaises(ValueError):
            remote_command(["bad\0argument"])
        args = ssh_args(document(), "one", "/state", "/identity")
        self.assertIn("StrictHostKeyChecking=yes", args)
        self.assertIn("BatchMode=yes", args)
        self.assertIn("ForwardAgent=no", args)
        self.assertIn("HostKeyAlias=device-links-one", args)


if __name__ == "__main__":
    unittest.main()
