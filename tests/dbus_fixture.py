"""KDE Connect lifecycle fixture, launched only on a private test D-Bus.

No network, keyring, real device pairing or authorization files are used.
The driver controls object registration separately from the paired flag so it
can exercise the exact UnknownObject race from a delayed identity plugin.
"""
import json
import sys

from PySide6.QtCore import ClassInfo, Property, QCoreApplication, QObject, Slot
from PySide6.QtDBus import QDBusConnection

from test_model import document

SERVICE = "org.amber.DeviceLinks.Fixture"
BASE = "/modules/kdeconnect"
ID = "fixturepeer"
PATH = f"{BASE}/devices/{ID}"
PLUGIN = "kdeconnect_devicelinks"


@ClassInfo(**{"D-Bus Interface": "org.kde.kdeconnect.daemon"})
class Daemon(QObject):
    @Slot(bool, bool, result="QStringList")
    def devices(self, _reachable, _paired):
        return [ID]

    @Slot(str)
    def setAnnouncedName(self, _name):
        pass

    @Slot()
    def forceOnNetworkChange(self):
        pass


@ClassInfo(**{"D-Bus Interface": "org.kde.kdeconnect.device"})
class Device(QObject):
    def __init__(self, fixture):
        super().__init__()
        self.fixture = fixture
        self.stage = "discovered"
        self.code = "A1B2C3D4"
        self.certificate = "fixture-certificate"

    name = Property(str, lambda self: "other", constant=True)
    isReachable = Property(bool, lambda self: self.stage != "offline")
    isPaired = Property(bool, lambda self: self.stage in ("paired", "announced", "ready", "complete", "offline"))
    isPairRequested = Property(bool, lambda self: self.stage == "pending")
    isPairRequestedByPeer = Property(bool, lambda self: self.stage == "incoming")
    supportedPlugins = Property("QStringList", lambda self: [PLUGIN])

    @Slot(result="QStringList")
    def loadedPlugins(self):
        return [PLUGIN] if self.stage in ("announced", "ready", "complete") else []

    @Slot(result=int)
    def pairStateAsInt(self):
        return 3 if self.isPaired else 2 if self.isPairRequestedByPeer else 1 if self.isPairRequested else 0

    @Slot(result=str)
    def verificationKey(self):
        return self.code

    @Slot(result=str)
    def encryptionInfo(self):
        return self.certificate

    @Slot()
    def requestPairing(self):
        self.fixture.history.append("requestPairing")
        self.fixture.transition("pending")

    @Slot()
    def acceptPairing(self):
        self.fixture.history.append("acceptPairing")
        self.fixture.transition("paired")

    @Slot()
    def cancelPairing(self):
        self.fixture.history.append("cancelPairing")
        self.fixture.transition("discovered")

    @Slot()
    def unpair(self):
        self.fixture.history.append("unpair")
        self.fixture.transition("discovered")


@ClassInfo(**{"D-Bus Interface": "org.kde.kdeconnect.device.devicelinks"})
class Plugin(QObject):
    def __init__(self, fixture):
        super().__init__()
        self.fixture = fixture

    @Slot(str, result=bool)
    def publish(self, _document):
        self.fixture.history.append("publish")
        if self.fixture.device.stage == "ready":
            # Vanish after the readiness check and successful publish reply.
            self.fixture.bus.unregisterObject(PATH + "/devicelinks")
        return True

    @Slot(result=str)
    def remoteDocument(self):
        self.fixture.history.append("remoteDocument")
        return json.dumps(document()) if self.fixture.device.stage == "complete" else ""


@ClassInfo(**{"D-Bus Interface": "org.amber.DeviceLinks.Fixture"})
class Fixture(QObject):
    def __init__(self, bus):
        super().__init__()
        self.bus = bus
        self.history = []
        self.daemon = Daemon()
        self.device = Device(self)
        self.plugin = Plugin(self)
        self.bus.registerObject(BASE, self.daemon, QDBusConnection.ExportAllContents)
        self.transition("discovered")

    @Slot(str)
    def transition(self, stage):
        self.bus.unregisterObject(PATH + "/devicelinks")
        self.bus.unregisterObject(PATH)
        self.device.stage = stage
        if stage != "gone":
            self.bus.registerObject(PATH, self.device, QDBusConnection.ExportAllContents)
        if stage in ("ready", "complete"):
            self.bus.registerObject(PATH + "/devicelinks", self.plugin, QDBusConnection.ExportAllContents)

    @Slot(str)
    def setCode(self, code):
        self.device.code = code

    @Slot(str)
    def setCertificate(self, certificate):
        self.device.certificate = certificate

    @Slot(result=str)
    def calls(self):
        return json.dumps(self.history)


if __name__ == "__main__":
    app = QCoreApplication([])
    bus = QDBusConnection.sessionBus()
    if not bus.registerService(SERVICE):
        sys.exit("Could not register isolated pairing fixture")
    fixture = Fixture(bus)
    if not bus.registerObject("/fixture", fixture, QDBusConnection.ExportAllContents):
        sys.exit("Could not export isolated pairing fixture")
    print("READY", flush=True)
    sys.exit(app.exec())
