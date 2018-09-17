#pragma once

#include <Sailfish/Crypto/key.h>
#include <Sailfish/Crypto/cryptomanager.h>

namespace Sailfish {
    namespace Crypto {
        class Request;
    }
}

class GenerateKeyRequests : public QObject {
    Q_OBJECT

public:
    static Sailfish::Crypto::Key createStoredKey(
        const QString& keyName,
        const QString& collectionName,
        const QString& dbName,
        const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        const Sailfish::Crypto::CryptoManager::Operations operations,
        const Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const std::size_t keyLength,
        const QString& pluginName);

    static Sailfish::Crypto::Key createKey(
        const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        const Sailfish::Crypto::CryptoManager::Operations operations,
        const Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const std::size_t keyLength,
        const QString& pluginName);
};
