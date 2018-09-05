#pragma once

#include <Sailfish/Crypto/key.h>

class CipherDecipherRequests : public QObject {
    Q_OBJECT

public:
    QByteArray cipherText(
        const Sailfish::Crypto::Key& key,
        const QByteArray& iv,
        const QByteArray& plainText,
        const Sailfish::Crypto::CryptoManager::BlockMode blockMode) const;

    QByteArray decipherText(
        const Sailfish::Crypto::Key& key,
        const QByteArray& iv,
        const QByteArray& ciphertext,
        const Sailfish::Crypto::CryptoManager::BlockMode blockMode) const;
};
