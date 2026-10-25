"""OpenSSH transport. No discovery packets ever contain commands or passwords."""
import base64
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys

# Non-interactive sshd sessions do not inherit the user's Nix profile PATH.
# The integration installs both the app and NixOS's setuid sudo wrapper at
# stable system paths, so the remote worker never depends on shell startup.
REMOTE_WORKER = os.environ.get("DEVICE_LINKS_REMOTE_WORKER", "/run/current-system/sw/bin/device-links")
SUDO = os.environ.get("DEVICE_LINKS_SUDO") or (
    "/run/wrappers/bin/sudo" if os.path.exists("/run/wrappers/bin/sudo") else "sudo")


def ssh_args(peer, device_id, state, identity):
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2",
            "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
            "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
            "-o", "ControlMaster=no", "-o", "ControlPath=none",
            "-o", f"UserKnownHostsFile={Path(state) / 'known_hosts'}",
            "-o", f"HostKeyAlias=device-links-{device_id}",
            "-i", str(identity), "-p", str(peer["sshPort"]),
            f"{peer['user']}@{peer['hostname']}.local"]


def remote_command(argv):
    if not argv or any(not isinstance(a, str) or "\0" in a for a in argv):
        raise ValueError("Expected a command and arguments")
    return shlex.join(argv)


def emit(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def read_message():
    line = sys.stdin.buffer.readline(131073)
    if not line:
        raise EOFError()
    if len(line) > 131072:
        raise ValueError("Oversized control message")
    return json.loads(line)


def sudo_worker():
    """One SSH connection owns one parent-PID sudo ticket; password is never kept.

    Commands are noninteractive, with stdin closed. stdin/stdout on this helper
    are framed control messages, not a terminal or a shell command language.
    """
    proc = None

    def stop(_sig=None, _frame=None):
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        raise EOFError()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGHUP, stop)
    try:
        while True:
            request = read_message()
            argv = request.get("argv")
            remote_command(argv)
            remember = False
            valid = subprocess.run([SUDO, "-n", "-v"], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if not valid:
                for attempt in range(1, 4):
                    emit({"type": "auth", "attempt": attempt})
                    answer = read_message()
                    if answer.get("cancel"):
                        break
                    password = answer.get("password")
                    if not isinstance(password, str) or "\n" in password or "\0" in password or len(password) > 4096:
                        break
                    remember = answer.get("remember") is True
                    auth = subprocess.run([SUDO, "-S", "-p", "", "-v"],
                                          input=(password + "\n").encode(),
                                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    password = None
                    answer.clear()
                    valid = auth.returncode == 0
                    if valid:
                        break
                if not valid:
                    emit({"type": "done", "code": 130, "remember": False})
                    continue
            else:
                remember = request.get("remember") is True

            proc = subprocess.Popen([SUDO, "-n", "--", *argv], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            streams = {proc.stdout.fileno(): "stdout", proc.stderr.fileno(): "stderr"}
            while streams:
                ready, _, _ = select.select([*streams, sys.stdin.fileno()], [], [], 1)
                for fd in ready:
                    if fd == sys.stdin.fileno():
                        # Disconnect/cancel kills only this worker's command group.
                        stop()
                    data = os.read(fd, 16384)
                    if not data:
                        del streams[fd]
                    else:
                        emit({"type": streams[fd], "data": base64.b64encode(data).decode()})
            code = proc.wait()
            proc = None
            if not remember:
                subprocess.run([SUDO, "-k"], check=False)
            emit({"type": "done", "code": code, "remember": remember})
    except (EOFError, BrokenPipeError):
        pass
    finally:
        if proc and proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        subprocess.run([SUDO, "-k"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
