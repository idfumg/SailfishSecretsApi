#include "digestrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/calculatedigestrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

QByteArray DigestRequests::digest(
    const QByteArray& data,
    const Sailfish::Crypto::CryptoManager::SignaturePadding padding,
    const Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
    const QString& pluginName)
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    CalculateDigestRequest request;
    request.setManager(&manager);
    request.setPadding(padding);
    request.setDigestFunction(digestFunction);
    request.setCryptoPluginName(pluginName);
    request.setData(data);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        return {};
    }

    return request.digest();
}
