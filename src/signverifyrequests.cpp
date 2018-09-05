#include "signverifyrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/signrequest.h>
#include <Sailfish/Crypto/verifyrequest.h>
#include <Sailfish/Crypto/generatestoredkeyrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

QByteArray SignVerifyRequests::sign(const Sailfish::Crypto::Key& key,
                                    const QByteArray& data)
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    SignRequest request;
    request.setManager(&manager);
    request.setKey(key);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.setPadding(Sailfish::Crypto::CryptoManager::SignaturePaddingNone);
    request.setDigestFunction(CryptoManager::DigestSha256);
    request.setData(data);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }

    return request.signature();
}

bool SignVerifyRequests::verify(const Sailfish::Crypto::Key& key,
                                const QByteArray& data,
                                const QByteArray& signature)
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    VerifyRequest request;
    request.setManager(&manager);
    request.setKey(key);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.setPadding(Sailfish::Crypto::CryptoManager::SignaturePaddingNone);
    request.setDigestFunction(CryptoManager::DigestSha256);
    request.setSignature(signature);
    request.setData(data);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }

    return request.verificationStatus() == CryptoManager::VerificationSucceeded;
}
