#include "cipherdecipherrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/cipherrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

QByteArray CipherDecipherRequests::cipherText(
    const Sailfish::Crypto::Key& key,
    const QByteArray& iv,
    const QByteArray& plainText,
    const Sailfish::Crypto::CryptoManager::BlockMode blockMode)
{
    qDebug() << Q_FUNC_INFO;

    QByteArray ciphertext;

    CryptoManager manager;
    CipherRequest request;
    request.setManager(&manager);
    request.setCipherMode(CipherRequest::InitializeCipher);
    request.setKey(key);
    request.setBlockMode(blockMode);
    request.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
    request.setInitializationVector(iv);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }

    // Update the cipher session with data to encrypt.
    for (int i = 0; i < plainText.size(); ++i) {
        request.setCipherMode(CipherRequest::UpdateCipher);
        request.setData(QByteArray(1, plainText[i]));
        request.startRequest();
        request.waitForFinished();
        if (not IsRequestWasSuccessful(&request)) {
            return {};
        }
        ciphertext.append(request.generatedData());
    }

    request.setCipherMode(CipherRequest::FinalizeCipher);
    request.startRequest();
    request.waitForFinished();
    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }
    ciphertext.append(request.generatedData());

    return ciphertext;
}
//#warning stream cipher with auth code
QByteArray CipherDecipherRequests::decipherText(
    const Sailfish::Crypto::Key& key,
    const QByteArray& iv,
    const QByteArray& ciphertext,
    const Sailfish::Crypto::CryptoManager::BlockMode blockMode)
{
    qDebug() << Q_FUNC_INFO;

    QByteArray plaintext;

    CryptoManager manager;
    CipherRequest request;
    request.setManager(&manager);
    request.setCipherMode(CipherRequest::InitializeCipher);
    request.setKey(key);
    request.setBlockMode(blockMode);
    request.setOperation(Sailfish::Crypto::CryptoManager::OperationDecrypt);
    request.setInitializationVector(iv);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }

    // Update the cipher session with data to encrypt.
    for (int i = 0; i < ciphertext.size(); ++i) {
        request.setCipherMode(CipherRequest::UpdateCipher);
        request.setData(QByteArray(1, ciphertext[i]));
        request.startRequest();
        request.waitForFinished();
        if (not IsRequestWasSuccessful(&request)) {
            return {};
        }
        plaintext.append(request.generatedData());
    }

    request.setCipherMode(CipherRequest::FinalizeCipher);
    request.startRequest();
    request.waitForFinished();
    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }
    plaintext.append(request.generatedData());

    return plaintext;
}
