#pragma once

#include <Sailfish/Crypto/key.h>

class EncryptDecryptRequests : public QObject {
    Q_OBJECT

public:
    QByteArray encrypt(
        const Sailfish::Crypto::Key& key,
        const QByteArray& iv,
        const QByteArray& plainText,
        const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray& authCode = "",
        QByteArray* authTag = nullptr) const;

    QByteArray decrypt(
        const Sailfish::Crypto::Key& key,
        const QByteArray& iv,
        const QByteArray& cipherText,
        const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray& authCode = "",
        QByteArray* authTag = nullptr) const;
};
