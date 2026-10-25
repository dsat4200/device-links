"""Explicit D-Bus calls, without QDBusInterface's cached introspection.

Qt can report isValid() for an interface whose object does not exist. KDE
Connect creates/removes plugin objects during pairing, so readiness must come
from real method replies, never that cached flag.
"""
from PySide6.QtDBus import QDBus, QDBusConnection, QDBusMessage, QDBusVariant

SERVICE = "org.kde.kdeconnect"
BASE = "/modules/kdeconnect"
PLUGIN = "kdeconnect_devicelinks"
UNAVAILABLE = {
    "org.freedesktop.DBus.Error.ServiceUnknown",
    "org.freedesktop.DBus.Error.NameHasNoOwner",
    "org.freedesktop.DBus.Error.Disconnected",
    "org.freedesktop.DBus.Error.NoReply",
    "org.freedesktop.DBus.Error.Timeout",
}
NOT_READY = UNAVAILABLE | {
    "org.freedesktop.DBus.Error.UnknownObject",
    "org.freedesktop.DBus.Error.UnknownInterface",
    "org.freedesktop.DBus.Error.UnknownMethod",
}


class DBusError(RuntimeError):
    def __init__(self, obj, method, reply):
        self.name = reply.errorName()
        self.details = {
            "service": obj.service, "path": obj.path, "interface": obj.interface,
            "method": method, "errorName": self.name,
            "errorMessage": reply.errorMessage()[:1024],
        }
        super().__init__(f"{obj.path}: {obj.interface}.{method}: "
                         f"{self.name}: {reply.errorMessage()[:1024]}")


class Object:
    def __init__(self, path, name, service=SERVICE):
        self.path, self.interface, self.service = path, name, service

    def invoke(self, method, *args):
        message = QDBusMessage.createMethodCall(self.service, self.path, self.interface, method)
        message.setArguments(list(args))
        # No nested GUI event loop while a snapshot is read. A modal approval
        # dialog may process timers, but a D-Bus call must not re-enter tick().
        reply = QDBusConnection.sessionBus().call(message, QDBus.Block, 3000)
        if reply.type() == QDBusMessage.ErrorMessage:
            raise DBusError(self, method, reply)
        args = reply.arguments()
        value = args[0] if args else None
        return value.variant() if isinstance(value, QDBusVariant) else value

    def property(self, name):
        properties = Object(self.path, "org.freedesktop.DBus.Properties", self.service)
        return properties.invoke("Get", self.interface, name)


def interface(path, name):
    return Object(path, name)


def call(obj, method, *args):
    return obj.invoke(method, *args)
