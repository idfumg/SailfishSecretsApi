#include "encryptdecryptrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/encryptrequest.h>
#include <Sailfish/Crypto/decryptrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

QByteArray EncryptDecryptRequests::encrypt(
    const Sailfish::Crypto::Key& key,
    const QByteArray& iv,
    const QByteArray& plainText,
    const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
    const Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
    const QString &pluginName,
    const QByteArray& authCode,
    QByteArray* authTag) const
{
    qDebug() << Q_FUNC_INFO;

    if (not authCode.isEmpty() and not authTag) {
        throw std::runtime_error("Auth tag not specified when auth code is");
    }

    CryptoManager manager;
    EncryptRequest request;
    request.setManager(&manager);
    request.setData(plainText);
    request.setKey(key);
    request.setInitializationVector(iv);
    request.setBlockMode(blockMode);
    request.setPadding(padding);
    request.setCryptoPluginName(pluginName);
    if (not authCode.isEmpty()) {
        request.setAuthenticationData(authCode);
    }
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when encrypt";
        throw std::runtime_error("Error when encrypt");
    }

    if (not authCode.isEmpty()) {
        *authTag = request.authenticationTag();
    }

    return request.ciphertext();
}

QByteArray EncryptDecryptRequests::decrypt(
    const Key& key,
    const QByteArray& iv,
    const QByteArray& cipherText,
    const CryptoManager::BlockMode blockMode,
    const CryptoManager::EncryptionPadding padding,
    const QString &pluginName,
    const QByteArray& authCode,
    QByteArray* authTag) const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    DecryptRequest request;
    request.setManager(&manager);
    request.setData(cipherText);
    request.setKey(key);
    request.setInitializationVector(iv);
    request.setBlockMode(blockMode);
    request.setPadding(padding);
    request.setCryptoPluginName(pluginName);
    if (not authCode.isEmpty()) {
        request.setAuthenticationData(authCode);
    }
    if (not authCode.isEmpty() and authTag) {
        request.setAuthenticationTag(*authTag);
    }
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when decrypt";
        throw std::runtime_error("Error when decrypt");
    }

    return request.plaintext();
}
