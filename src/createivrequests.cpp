#include "createivrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/generateinitializationvectorrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

QByteArray CreateIVRequests::createIV(
    const Sailfish::Crypto::CryptoManager::Algorithm algorithm,
    const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
    const std::size_t keyLength)
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    GenerateInitializationVectorRequest request;
    request.setManager(&manager);
    request.setAlgorithm(algorithm);
    request.setKeySize(keyLength);
    request.setBlockMode(blockMode);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating IV";
        throw std::runtime_error("Error when generating IV");
    }

    return request.generatedInitializationVector();
}
