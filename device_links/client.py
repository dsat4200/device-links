import json
import os
from pathlib import Path
import socket


def runtime():
    root = os.environ.get("XDG_RUNTIME_DIR")
    if not root:
        raise RuntimeError("No graphical user runtime directory; log in locally first")
    path = Path(root) / "device-links"
    path.mkdir(mode=0o700, exist_ok=True)
    st = path.stat()
    if path.is_symlink() or st.st_uid != os.getuid() or st.st_mode & 0o077:
        raise RuntimeError("Unsafe Device Links runtime directory")
    return path


def connect(request, timeout=30):
    sock = socket.socket(socket.AF_UNIX)
    sock.settimeout(timeout)
    try:
        sock.connect(str(runtime() / "control.sock"))
    except OSError as exc:
        sock.close()
        raise RuntimeError("Device Links is not running. Open it from the launcher or start device-links.service") from exc
    sock.sendall((json.dumps(request) + "\n").encode())
    return sock


def rpc(request, timeout=30):
    with connect(request, timeout) as sock:
        line = sock.makefile("rb").readline(131073)
        if not line or len(line) > 131072:
            raise RuntimeError("Invalid response from Device Links")
        result = json.loads(line)
        if "error" in result:
            raise RuntimeError(result["error"])
        return result
