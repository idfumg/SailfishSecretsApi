#pragma once

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"

class DigestRequests : public QObject {
    Q_OBJECT

public:
    static QByteArray digest(
        const QByteArray& data,
        const Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        const Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QString& pluginName);
};
