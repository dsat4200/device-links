import argparse
import base64
import json
import os
import signal
import subprocess
import sys

from . import VERSION
from .client import connect, rpc
from .transport import remote_command, ssh_args, sudo_worker


def main():
    parser = argparse.ArgumentParser(description="Discover, link and diagnose configured LAN devices. Pairing approval is GUI-only. Remote desktop viewing belongs to Remmina.")
    parser.add_argument("--version", action="version", version=VERSION)
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("gui", help="Open the Device Links window")
    serve = sub.add_parser("serve", help="Run the graphical-session backend")
    serve.add_argument("--config", default=os.environ.get("DEVICE_LINKS_CONFIG", "/etc/device-links/config.json"))
    serve.add_argument("--show", action="store_true")
    for cmd in ("list", "scan", "doctor"):
        p = sub.add_parser(cmd, help=f"{cmd.title()} linked/discovered device status")
        if cmd == "doctor":
            p.add_argument("target", nargs="?")
        p.add_argument("--json", action="store_true")
    for cmd in ("exec", "gsudo"):
        p = sub.add_parser(cmd, help="Execute through verified SSH" if cmd == "exec" else "Run a noninteractive remote admin command; password prompt appears locally")
        p.add_argument("target")
        if cmd == "gsudo":
            p.add_argument("purpose")
        p.add_argument("argv", nargs=argparse.REMAINDER)
    sub.add_parser("_sudo-worker", help=argparse.SUPPRESS)
    args = parser.parse_args()
    command = args.command or "gui"
    if command == "_sudo-worker":
        sudo_worker()
        return 0
    if command == "serve":
        from PySide6.QtCore import QTimer
        from PySide6.QtWidgets import QApplication
        from .backend import Backend
        app = QApplication(sys.argv[:1])
        app.setApplicationName("Device Links")
        app.setDesktopFileName("org.amber.DeviceLinks")
        app.setQuitOnLastWindowClosed(False)
        backend = Backend(app, args.config)
        if args.show:
            backend.show()
        signal.signal(signal.SIGTERM, lambda *_: app.quit())
        signal.signal(signal.SIGINT, lambda *_: app.quit())
        pulse = QTimer()
        pulse.timeout.connect(lambda: None)
        pulse.start(250)
        return app.exec()
    if command == "gui":
        try:
            rpc({"op": "show"})
        except RuntimeError:
            subprocess.run(["systemctl", "--user", "start", "device-links.service"], check=True)
            import time
            for attempt in range(40):
                try:
                    rpc({"op": "show"})
                    break
                except RuntimeError:
                    if attempt == 39:
                        raise
                    time.sleep(0.25)
        return 0
    if command in ("list", "scan", "doctor"):
        result = rpc({"op": command})
        if getattr(args, "target", None):
            result["devices"] = [d for d in result["devices"] if args.target in (d["hostname"], d["id"])]
            if not result["devices"]:
                raise RuntimeError("Unknown configured device")
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Device Links {result['version']} on {result['hostname']}")
            for row in result["devices"]:
                print(f"{row['hostname']}: {'online' if row['reachable'] else 'offline'}, {'linked' if row['linked'] else 'not linked'}" + (f" — {row['problem']}" if row["problem"] else ""))
            for field in ("identityProblem", "discoveryProblem"):
                if result.get(field):
                    print(result[field], file=sys.stderr)
        return 1 if result.get("identityProblem") or result.get("discoveryProblem") or any(d["problem"] for d in result["devices"]) else 0
    argv = args.argv[1:] if args.argv[:1] == ["--"] else args.argv
    remote_command(argv)
    if command == "exec":
        peer = rpc({"op": "resolve", "target": args.target})
        return subprocess.call([*ssh_args(peer["peer"], peer["id"], peer["state"], peer["identity"]), remote_command(argv)])
    with connect({"op": "gsudo", "target": args.target, "purpose": args.purpose, "argv": argv}, timeout=None) as sock:
        for line in sock.makefile("rb"):
            result = json.loads(line)
            if "error" in result:
                print(result["error"], file=sys.stderr)
                return 255
            if result["type"] in ("stdout", "stderr"):
                stream = sys.stdout.buffer if result["type"] == "stdout" else sys.stderr.buffer
                stream.write(base64.b64decode(result["data"], validate=True))
                stream.flush()
            elif result["type"] == "done":
                return result["code"]
    return 255


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"device-links: {exc}", file=sys.stderr)
        sys.exit(1)
