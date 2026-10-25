"""Protocol tests use a fake sudo, never real privilege escalation."""
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class SudoTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        sudo = root / "sudo"
        sudo.write_text(f'''#!{sys.executable}
import os, pathlib, subprocess, sys
ticket = pathlib.Path(os.environ['TICKET'])
args = sys.argv[1:]
if args == ['-k']:
    ticket.unlink(missing_ok=True)
    sys.exit(0)
if args == ['-n', '-v']:
    sys.exit(0 if ticket.exists() else 1)
if args == ['-S', '-p', '', '-v']:
    valid = sys.stdin.readline().rstrip('\\n') == 'correct'
    if valid: ticket.touch()
    sys.exit(0 if valid else 1)
if args[:2] == ['-n', '--'] and ticket.exists():
    sys.exit(subprocess.call(args[2:]))
sys.exit(1)
''')
        sudo.chmod(0o755)
        self.ticket = root / "ticket"
        env = os.environ | {"PATH": str(root) + os.pathsep + os.environ["PATH"], "TICKET": str(self.ticket),
                           "DEVICE_LINKS_SUDO": str(sudo)}
        self.proc = subprocess.Popen([sys.executable, "-m", "device_links", "_sudo-worker"],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        self.addCleanup(self.stop)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        self.proc.stdout.close()
        self.proc.stderr.close()

    def send(self, message):
        self.proc.stdin.write((json.dumps(message) + "\n").encode())
        self.proc.stdin.flush()

    def receive(self):
        import select
        self.assertTrue(select.select([self.proc.stdout], [], [], 5)[0], "worker response timed out")
        return json.loads(self.proc.stdout.readline())

    def command(self):
        self.send({"argv": [sys.executable, "-c", "import sys; print('ok'); print('err', file=sys.stderr); assert sys.stdin.read() == ''"]})
        self.assertEqual(self.receive()["type"], "auth")

    def complete(self):
        messages = []
        while True:
            msg = self.receive()
            messages.append(msg)
            if msg["type"] == "done":
                return messages

    def test_password_not_given_to_command_and_ticket_invalidated(self):
        self.command()
        self.send({"password": "correct", "remember": False})
        messages = self.complete()
        self.assertEqual(messages[-1]["code"], 0)
        output = b"".join(base64.b64decode(m["data"]) for m in messages if "data" in m)
        self.assertIn(b"ok", output)
        self.assertNotIn(b"correct", output)
        self.assertFalse(self.ticket.exists())

    def test_remember_is_connection_ticket_and_eof_revokes(self):
        self.command()
        self.send({"password": "correct", "remember": True})
        self.assertTrue(self.complete()[-1]["remember"])
        self.assertTrue(self.ticket.exists())
        self.send({"argv": [sys.executable, "-c", "print('second')"], "remember": True})
        self.assertNotEqual(self.receive()["type"], "auth")
        self.complete()
        self.stop()
        self.assertFalse(self.ticket.exists())

    def test_cancel_and_bad_password_do_not_execute(self):
        self.command()
        self.send({"password": "wrong"})
        self.assertEqual(self.receive()["attempt"], 2)
        self.send({"cancel": True})
        result = self.receive()
        self.assertEqual(result["type"], "done")
        self.assertEqual(result["code"], 130)
        self.assertFalse(self.ticket.exists())


if __name__ == "__main__":
    unittest.main()
