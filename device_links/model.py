"""Pure validation and app-owned state. No Qt, network access or credential reads."""
import base64
import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tempfile

NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]{0,62}\Z")
USER = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
DEVICE_ID = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")


def ssh_key(value):
    if not isinstance(value, str) or len(value) > 1024:
        raise ValueError("Invalid SSH public key")
    parts = value.split()
    if len(parts) < 2 or parts[0] != "ssh-ed25519":
        raise ValueError("Only Ed25519 public keys are accepted")
    try:
        raw = base64.b64decode(parts[1], validate=True)
    except Exception as exc:
        raise ValueError("Invalid SSH key encoding") from exc
    # SSH wire format: string 'ssh-ed25519', string 32-byte public key.
    if len(raw) != 51 or raw[:19] != b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20":
        raise ValueError("Invalid Ed25519 key structure")
    return f"ssh-ed25519 {parts[1]}"


def descriptor(document, roster):
    if not isinstance(document, dict) or document.get("schema") != 1:
        raise ValueError("Incompatible identity schema; rebuild the peer")
    host = document.get("hostname", "")
    user = document.get("user", "")
    if not NAME.fullmatch(host) or host not in roster:
        raise ValueError("Peer is not in this configuration's device roster")
    if not USER.fullmatch(user):
        raise ValueError("Invalid peer username")
    port = document.get("sshPort", 22)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Invalid SSH port")
    endpoints = document.get("desktopEndpoints", [])
    if not isinstance(endpoints, list) or len(endpoints) > 8:
        raise ValueError("Invalid desktop capabilities")
    clean = []
    for endpoint in endpoints:
        if not isinstance(endpoint, dict) or endpoint.get("protocol") not in ("RDP", "VNC"):
            raise ValueError("Unsupported desktop protocol")
        p = endpoint.get("port")
        if type(p) is not int or not 1 <= p <= 65535:
            raise ValueError("Invalid desktop port")
        clean.append({"protocol": endpoint["protocol"], "port": p})
    return {"schema": 1, "hostname": host, "user": user, "sshPort": port,
            "publicKey": ssh_key(document.get("publicKey")),
            "hostKey": ssh_key(document.get("hostKey")), "desktopEndpoints": clean}


def atomic(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError(f"Refusing symlink: {path.name}")
    fd, tmp = tempfile.mkstemp(prefix=".device-links-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


class State:
    def __init__(self, root, roster):
        self.root = Path(root)
        self.roster = roster
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        mode = self.root.stat()
        if self.root.is_symlink() or mode.st_uid != os.getuid() or stat.S_IMODE(mode.st_mode) & 0o077:
            raise ValueError("Device Links state directory must be owned by you and mode 0700")
        path = self.root / "peers.json"
        self.peers = json.loads(path.read_text()) if path.exists() else {}

    def save(self):
        atomic(self.root / "peers.json", json.dumps(self.peers, indent=2) + "\n")

    def approve(self, device_id, certificate):
        if not DEVICE_ID.fullmatch(device_id) or not certificate or len(certificate) > 8192:
            raise ValueError("Invalid pairing identity")
        self.peers[device_id] = {"certificate": certificate, "approved": True}
        self.save()

    def receive(self, device_id, certificate, document):
        peer = self.peers.get(device_id, {})
        if not peer.get("approved") or peer.get("certificate") != certificate:
            raise ValueError("Peer certificate has not been approved locally")
        data = descriptor(document, self.roster)
        old = peer.get("descriptor")
        if old and (old["hostKey"] != data["hostKey"] or old["publicKey"] != data["publicKey"] or old["hostname"] != data["hostname"]):
            raise ValueError("Peer identity changed; unlink and approve it again")
        if any(key != device_id and value.get("descriptor", {}).get("hostname") == data["hostname"]
               for key, value in self.peers.items()):
            raise ValueError("A different identity already uses this device name")
        peer["descriptor"] = data
        self.save()
        self.reconcile()
        return data

    def forget(self, device_id):
        self.peers.pop(device_id, None)
        self.save()
        self.reconcile()

    def linked(self):
        return {key: value["descriptor"] for key, value in self.peers.items()
                if value.get("approved") and value.get("descriptor", {}).get("hostname") in self.roster}

    def reconcile(self):
        # Separate app-owned files: never edit ~/.ssh/authorized_keys.
        atomic(self.root / "authorized_keys", "".join(
            f"{p['publicKey']} device-links:{key}\n" for key, p in sorted(self.linked().items())))
        atomic(self.root / "known_hosts", "".join(
            f"device-links-{key},{p['hostname']}.local,[{p['hostname']}.local]:{p['sshPort']} {p['hostKey']}\n"
            for key, p in sorted(self.linked().items())))
    def ssh_config(self, identity):
        atomic(self.root / "ssh_config", "".join(
            f"Host device-links-{p['hostname']} {p['hostname']}.local\n"
            f"  HostName {p['hostname']}.local\n  User {p['user']}\n  Port {p['sshPort']}\n"
            f"  IdentityFile {identity}\n"
            f"  UserKnownHostsFile {self.root}/known_hosts\n"
            f"  HostKeyAlias device-links-{key}\n  StrictHostKeyChecking yes\n  IdentitiesOnly yes\n"
            for key, p in sorted(self.linked().items())))


def profile_path(directory, device_id, protocol):
    if not DEVICE_ID.fullmatch(device_id) or protocol not in ("SSH", "RDP", "VNC"):
        raise ValueError("Invalid profile identity")
    return Path(directory) / f"device-links-{device_id}-{protocol.lower()}.remmina"


def remmina_profiles(directory, device_id, peer, identity, known_hosts):
    """Merge only connection-owned fields; preserve Remmina display/user fields."""
    endpoints = [{"protocol": "SSH", "port": peer["sshPort"]}] + peer["desktopEndpoints"]
    written = []
    for endpoint in endpoints:
        protocol = endpoint["protocol"]
        path = profile_path(directory, device_id, protocol)
        ini = configparser.ConfigParser(interpolation=None, strict=False)
        if path.exists():
            ini.read(path)
        if not ini.has_section("remmina"):
            ini.add_section("remmina")
        values = {"name": f"{peer['hostname']} — {protocol}", "group": "My Devices",
                  "protocol": protocol, "server": f"{peer['hostname']}.local:{endpoint['port']}",
                  "username": peer["user"]}
        if protocol == "SSH":
            values.update(ssh_auth="1", ssh_privatekey=str(identity),
                          ssh_stricthostkeycheck="1")
        for key, value in values.items():
            ini.set("remmina", key, str(value))
        output = io.StringIO()
        ini.write(output, space_around_delimiters=False)
        if not path.exists() or path.read_text() != output.getvalue():
            atomic(path, output.getvalue())
        written.append(str(path))
    return written


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(base64.b64decode(ssh_key(key).split()[1])).digest()).decode().rstrip("=")
