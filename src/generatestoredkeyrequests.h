#pragma once

#include <Sailfish/Crypto/key.h>
#include <Sailfish/Crypto/cryptomanager.h>

namespace Sailfish {
    namespace Crypto {
        class Request;
    }
}

class GenerateStoredKeyRequests : public QObject {
    Q_OBJECT

public:
    Sailfish::Crypto::Key createStoredKey(
        const QString& keyName,
        const QString& collectionName,
        const QString& dbName,
        const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        const Sailfish::Crypto::CryptoManager::Operations operations,
        const std::size_t keyLength) const;
};
