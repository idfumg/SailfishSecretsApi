#include "generatekeyrequests.h"
#include "utils.h"

#include <Sailfish/Crypto/generatestoredkeyrequest.h>
#include <Sailfish/Crypto/generatekeyrequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;

namespace {

    RsaKeyPairGenerationParameters CreateGenParams(const std::size_t keyLength)
    {
        RsaKeyPairGenerationParameters result;
        result.setModulusLength(keyLength);
        return result;
    }

} // anonymous namespace

Key GenerateKeyRequests::createStoredKey(
    const QString& keyName,
    const QString& collectionName,
    const QString& dbName,
    const CryptoManager::Algorithm algorithm,
    const CryptoManager::Operations operations,
    const CryptoManager::DigestFunction digestFunction,
    const std::size_t keyLength,
    const QString& pluginName)
{
    qDebug() << Q_FUNC_INFO;

    /*
      Key derivation need for improve key security.
      Its used for iterable several times getting digest of the key using some salt
      which defense from dictionary attacks.
    */
    KeyDerivationParameters kdp;
    kdp.setKeyDerivationFunction(CryptoManager::KdfPkcs5Pbkdf2);
    kdp.setKeyDerivationMac(CryptoManager::MacHmac);
    kdp.setKeyDerivationDigestFunction(digestFunction);
    kdp.setIterations(16384);
    kdp.setSalt("my random salt");
    kdp.setOutputKeySize(keyLength);

    Key key;
    key.setAlgorithm(algorithm);
    key.setSize(keyLength);
    key.setOrigin(Key::OriginDevice);
    key.setOperations(operations);
    key.setIdentifier(Key::Identifier(keyName, collectionName, dbName));
    key.setComponentConstraints(
        Key::MetaData |
        Key::PublicKeyData |
        Key::PrivateKeyData);

    CryptoManager manager;
    GenerateStoredKeyRequest request;
    request.setManager(&manager);
    request.setKeyTemplate(key);
    request.setCryptoPluginName(pluginName);
    if ((algorithm == CryptoManager::AlgorithmRsa or
         algorithm == CryptoManager::AlgorithmGost) and
        (operations & CryptoManager::OperationSign or
         operations & CryptoManager::OperationVerify)) {
        request.setKeyPairGenerationParameters(CreateGenParams(key.size()));
    }
    request.setKeyDerivationParameters(kdp);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating key";
        throw std::runtime_error("Error when generating key");
    }

    return request.generatedKeyReference();
}

Key GenerateKeyRequests::createKey(
        const CryptoManager::Algorithm algorithm,
        const CryptoManager::Operations operations,
        const CryptoManager::DigestFunction digestFunction,
        const std::size_t keyLength,
        const QString& pluginName)
{
    qDebug() << Q_FUNC_INFO;

    /*
      Key derivation need for improve key security.
      Its used for iterable several times getting digest of the key using some salt
      which defense from dictionary attacks.
    */
    KeyDerivationParameters kdp;
    kdp.setKeyDerivationFunction(CryptoManager::KdfPkcs5Pbkdf2);
    kdp.setKeyDerivationMac(CryptoManager::MacHmac);
    kdp.setKeyDerivationDigestFunction(digestFunction);
    kdp.setIterations(16384);
    kdp.setSalt("my random salt");
    kdp.setOutputKeySize(keyLength);

    Key key;
    key.setAlgorithm(algorithm);
    key.setSize(keyLength);
    key.setOrigin(Key::OriginDevice);
    key.setOperations(operations);
    key.setComponentConstraints(
        Key::MetaData |
        Key::PublicKeyData |
        Key::PrivateKeyData);

    CryptoManager manager;
    GenerateKeyRequest request;
    request.setManager(&manager);
    request.setKeyTemplate(key);
    request.setCryptoPluginName(pluginName);
    if ((algorithm == CryptoManager::AlgorithmRsa or
         algorithm == CryptoManager::AlgorithmGost) and
        (operations & CryptoManager::OperationSign or
         operations & CryptoManager::OperationVerify)) {
        request.setKeyPairGenerationParameters(CreateGenParams(key.size()));
    }
    request.setKeyDerivationParameters(kdp);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating key";
        throw std::runtime_error("Error when generating key");
    }

    return request.generatedKey();
}
