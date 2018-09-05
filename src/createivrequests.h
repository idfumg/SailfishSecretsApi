#pragma once

#include <Sailfish/Crypto/key.h>
#include <Sailfish/Crypto/cryptomanager.h>

namespace Sailfish {
    namespace Crypto {
        class Request;
    }
}

class CreateIVRequests : public QObject {
    Q_OBJECT

public:
    QByteArray createIV(const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                        const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
                        const std::size_t keyLength) const;
};
