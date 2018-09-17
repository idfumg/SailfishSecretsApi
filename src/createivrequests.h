#pragma once

#include <Sailfish/Crypto/key.h>
#include <Sailfish/Crypto/cryptomanager.h>

class CreateIVRequests : public QObject {
    Q_OBJECT

public:
    static QByteArray createIV(
        const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const std::size_t keyLength,
        const QString& pluginName);
};
