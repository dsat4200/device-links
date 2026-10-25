// SPDX-License-Identifier: GPL-3.0-or-later
#include <KPluginFactory>
#include <QJsonDocument>
#include <QJsonObject>
#include <core/device.h>
#include <core/kdeconnectplugin.h>

class DeviceLinksPlugin : public KdeConnectPlugin {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.kde.kdeconnect.device.devicelinks")
public:
    using KdeConnectPlugin::KdeConnectPlugin;
    QString dbusPath() const override {
        return QStringLiteral("/modules/kdeconnect/devices/%1/devicelinks").arg(device()->id());
    }
    Q_SCRIPTABLE QString remoteDocument() const { return remote; }
    Q_SCRIPTABLE bool publish(const QString &document) {
        if (!device()->isPaired() || document.toUtf8().size() > 32768) return false;
        const auto json = QJsonDocument::fromJson(document.toUtf8());
        if (!json.isObject()) return false;
        NetworkPacket packet(QStringLiteral("org.amber.devicelinks.identity"));
        packet.set(QStringLiteral("document"), document);
        return sendPacket(packet);
    }
    void receivePacket(const NetworkPacket &packet) override {
        // Never execute anything or write files here. Python validates the schema
        // and separately requires local human approval bound to the certificate.
        if (!device()->isPaired()) return;
        const QString document = packet.get<QString>(QStringLiteral("document"));
        if (document.toUtf8().size() > 32768) return;
        if (!QJsonDocument::fromJson(document.toUtf8()).isObject()) return;
        remote = document;
    }
private:
    QString remote;
};
K_PLUGIN_CLASS_WITH_JSON(DeviceLinksPlugin, "kdeconnect_devicelinks.json")
#include "devicelinksplugin.moc"
