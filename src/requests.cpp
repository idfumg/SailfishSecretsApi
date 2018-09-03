#include "requests.h"

#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/generaterandomdatarequest.h>
#include <Sailfish/Crypto/seedrandomdatageneratorrequest.h>
#include <Sailfish/Crypto/generatestoredkeyrequest.h>
#include <Sailfish/Crypto/generateinitializationvectorrequest.h>
#include <Sailfish/Crypto/encryptrequest.h>
#include <Sailfish/Crypto/decryptrequest.h>
#include <Sailfish/Crypto/storedkeyrequest.h>
#include <Sailfish/Crypto/deletestoredkeyrequest.h>
#include <Sailfish/Crypto/cipherrequest.h>
#include <Sailfish/Crypto/signrequest.h>

#include <Sailfish/Secrets/secretmanager.h>
#include <Sailfish/Secrets/createcollectionrequest.h>
#include <Sailfish/Secrets/deletecollectionrequest.h>
#include <Sailfish/Secrets/collectionnamesrequest.h>
#include <Sailfish/Secrets/plugininforequest.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;
using namespace Sailfish::Secrets;

namespace {

    const QString KEY_NAME = QStringLiteral("ExampleKey");
    const QString COLLECTION_NAME = QLatin1String("ExampleCollection");
    const QString DB_NAME = QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite");
    const Key::Identifier keyIdentifier(KEY_NAME, COLLECTION_NAME, DB_NAME);

    bool IsRequestWasSuccessful(Sailfish::Crypto::Request* request)
    {
        qDebug() << "\n\n";
        qDebug() << request->status();
        qDebug() << request->result().code();
        qDebug() << request->result().errorMessage();

        return
            request->status() == Sailfish::Crypto::Request::Finished and
            request->result().code() == Sailfish::Crypto::Result::Succeeded;
    }

    bool IsRequestWasSuccessful(Sailfish::Secrets::Request* request)
    {
        qDebug() << "\n\n";
        qDebug() << request->status();
        qDebug() << request->result().code();
        qDebug() << request->result().errorMessage();

        return
            request->status() == Sailfish::Secrets::Request::Finished and
            request->result().code() == Sailfish::Secrets::Result::Succeeded;
    }

    bool IsCollectionExists(const QStringList& collectionNames,
                            const QString& name)
    {
        for (const auto& collectionName : collectionNames) {
            if (collectionName == name) {
                return true;
            }
        }
        return false;
    }

} // anonymous namespace

void Requests::getRandomData() const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    GenerateRandomDataRequest* const request = new GenerateRandomDataRequest;
    request->setManager(&manager);
    request->setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request->setCsprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName);
    request->setNumberBytes(128);
    request->startRequest();
    connect(request, &GenerateRandomDataRequest::statusChanged, [request] () {
        if (IsRequestWasSuccessful(request)) {
            qDebug() << request->generatedData();
        }

        request->deleteLater();
    });
}

void Requests::seedRandomGenerator() const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    SeedRandomDataGeneratorRequest* const request = new SeedRandomDataGeneratorRequest;
    request->setManager(&manager);
    request->setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request->setCsprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName);
    request->setEntropyEstimate(0.1);
    request->setSeedData(QByteArray("very random seed data"));
    request->startRequest();
    connect(request, &GenerateRandomDataRequest::statusChanged, [request] () {
        if (IsRequestWasSuccessful(request)) {
            qDebug() << "PRNG seeded successfuly";
        }

        request->deleteLater();
    });
}

bool Requests::isCollectionExists() const
{
    qDebug() << Q_FUNC_INFO;

    SecretManager manager;
    CollectionNamesRequest* const request = new CollectionNamesRequest;
    request->setManager(&manager);
    request->setStoragePluginName(DB_NAME);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    if (IsRequestWasSuccessful(request)) {
        const auto collectionNames = request->collectionNames();
        return IsCollectionExists(collectionNames, COLLECTION_NAME);
    }

    return false;
}

bool Requests::deleteCollection() const
{
    qDebug() << Q_FUNC_INFO;

    SecretManager manager;
    DeleteCollectionRequest* const request = new DeleteCollectionRequest;
    request->setManager(&manager);
    request->setStoragePluginName(DB_NAME);
    request->setCollectionName(COLLECTION_NAME);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    return IsRequestWasSuccessful(request);
}

bool Requests::createCollection() const
{
    qDebug() << Q_FUNC_INFO;

    SecretManager manager;
    CreateCollectionRequest* const request = new CreateCollectionRequest;
    request->setManager(&manager);
    // request->setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    // request->setAuthenticationPluginName(SecretManager::DefaultAuthenticationPluginName);
    request->setEncryptionPluginName("org.sailfishos.secrets.plugin.encryption.openssl");
    request->setStoragePluginName(DB_NAME);
    request->setCollectionName(COLLECTION_NAME);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    return IsRequestWasSuccessful(request);
}

Sailfish::Crypto::Key Requests::createTemplateKey() const
{
    qDebug() << Q_FUNC_INFO;

    Key keyTemplate;

    keyTemplate.setAlgorithm(CryptoManager::AlgorithmAes);
    keyTemplate.setSize(256);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(
        CryptoManager::OperationEncrypt |
        CryptoManager::OperationDecrypt |
        CryptoManager::OperationSign |
        CryptoManager::OperationVerify);
    keyTemplate.setIdentifier(keyIdentifier);
    keyTemplate.setComponentConstraints(
        Sailfish::Crypto::Key::MetaData |
        Sailfish::Crypto::Key::PublicKeyData |
        Sailfish::Crypto::Key::PrivateKeyData);

    return keyTemplate;
}

Sailfish::Crypto::Key Requests::createStoredKey(const Sailfish::Crypto::Key& keyTemplate) const
{
    qDebug() << Q_FUNC_INFO;

    KeyDerivationParameters kdp;
    kdp.setKeyDerivationFunction(CryptoManager::KdfPkcs5Pbkdf2);
    kdp.setKeyDerivationMac(CryptoManager::MacHmac);
    kdp.setKeyDerivationDigestFunction(CryptoManager::DigestSha512);
    kdp.setIterations(16384);
    kdp.setSalt(QByteArray("some random salt"));
    kdp.setOutputKeySize(256);

    CryptoManager manager;
    GenerateStoredKeyRequest request;
    request.setManager(&manager);
    request.setKeyTemplate(keyTemplate);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.setKeyDerivationParameters(kdp);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating key";
        throw std::runtime_error("Error when generating key");
    }

    return request.generatedKeyReference();
}

QByteArray Requests::createIV(const Sailfish::Crypto::Key& key) const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    GenerateInitializationVectorRequest request;
    request.setManager(&manager);
    request.setAlgorithm(key.algorithm());
    request.setKeySize(key.size());
    request.setBlockMode(CryptoManager::BlockModeCbc);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating IV";
        throw std::runtime_error("Error when generating IV");
    }

    return request.generatedInitializationVector();
}

QByteArray Requests::encrypt(const Sailfish::Crypto::Key& key,
                             const QByteArray& iv,
                             const QByteArray& plainText) const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    EncryptRequest request;
    request.setManager(&manager);
    request.setData(plainText);
    request.setKey(key);
    request.setInitializationVector(iv);
    request.setBlockMode(CryptoManager::BlockModeCbc);
    request.setPadding(CryptoManager::EncryptionPaddingNone);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when encrypt";
        throw std::runtime_error("Error when encrypt");
    }

    return request.ciphertext();
}

QByteArray Requests::decrypt(const Sailfish::Crypto::Key& key,
                             const QByteArray& iv,
                             const QByteArray& cipherText) const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    DecryptRequest request;
    request.setManager(&manager);
    request.setData(cipherText);
    request.setKey(key);
    request.setInitializationVector(iv);
    request.setBlockMode(CryptoManager::BlockModeCbc);
    request.setPadding(CryptoManager::EncryptionPaddingNone);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when decrypt";
        throw std::runtime_error("Error when decrypt");
    }

    return request.plaintext();
}

Sailfish::Crypto::Key Requests::getStoredKey() const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    StoredKeyRequest request;
    request.setManager(&manager);
    request.setIdentifier(keyIdentifier);
    request.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData | Key::SecretKeyData);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when getStoredKey";
        throw std::runtime_error("Error when getStoredKey");
    }

    return request.storedKey();
}

void Requests::pluginInfo() const
{
    qDebug() << Q_FUNC_INFO;

    SecretManager manager;
    PluginInfoRequest request;
    request.setManager(&manager);
    request.startRequest();
    request.waitForFinished();

    const auto PrintPluginInfo = [] (const QString& pluginType,
                                     const QVector<PluginInfo>& pluginInfos) {
        for (const auto& pluginInfo : pluginInfos) {
            qDebug() << ": " << pluginType << pluginInfo.name();
        }
    };

    if (IsRequestWasSuccessful(&request)) {
        PrintPluginInfo("storage plugin: ", request.storagePlugins());
        PrintPluginInfo("encryption plugin: ", request.encryptionPlugins());
        PrintPluginInfo("encrypted storage plugin: ", request.encryptedStoragePlugins());
        PrintPluginInfo("authentication plugin: ", request.authenticationPlugins());
    }
}

bool Requests::deleteStoredKey() const
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    DeleteStoredKeyRequest* const request = new DeleteStoredKeyRequest;
    request->setIdentifier(keyIdentifier);
    request->setManager(&manager);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    return IsRequestWasSuccessful(request);
}

QByteArray Requests::cipherText(const Sailfish::Crypto::Key& key,
                                const QByteArray& iv,
                                const QByteArray& plainText) const
{
    qDebug() << Q_FUNC_INFO;

    QByteArray ciphertext;

    CryptoManager manager;
    CipherRequest request;
    request.setManager(&manager);
    request.setCipherMode(CipherRequest::InitializeCipher);
    request.setKey(key);
    request.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
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

QByteArray Requests::decipherText(const Sailfish::Crypto::Key& key,
                                  const QByteArray& iv,
                                  const QByteArray& ciphertext) const
{
    qDebug() << Q_FUNC_INFO;

    QByteArray plaintext;

    CryptoManager manager;
    CipherRequest request;
    request.setManager(&manager);
    request.setCipherMode(CipherRequest::InitializeCipher);
    request.setKey(key);
    request.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
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

QByteArray Requests::sign(const Sailfish::Crypto::Key& key,
                          const QByteArray& data) const
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

Sailfish::Crypto::Key Requests::createStoredKeyRSA() const
{
    qDebug() << Q_FUNC_INFO;

    Key keyTemplate;

    keyTemplate.setAlgorithm(CryptoManager::AlgorithmRsa);
    keyTemplate.setSize(256);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(
        CryptoManager::OperationEncrypt |
        CryptoManager::OperationDecrypt |
        CryptoManager::OperationSign |
        CryptoManager::OperationVerify);
    keyTemplate.setIdentifier(keyIdentifier);
    keyTemplate.setComponentConstraints(
        Sailfish::Crypto::Key::MetaData |
        Sailfish::Crypto::Key::PublicKeyData |
        Sailfish::Crypto::Key::PrivateKeyData);

    KeyDerivationParameters kdp;
    kdp.setKeyDerivationFunction(CryptoManager::KdfPkcs5Pbkdf2);
    kdp.setKeyDerivationMac(CryptoManager::MacHmac);
    kdp.setKeyDerivationDigestFunction(CryptoManager::DigestSha512);
    kdp.setIterations(16384);
    kdp.setSalt(QByteArray("some random salt"));
    kdp.setOutputKeySize(256);

    CryptoManager manager;
    GenerateStoredKeyRequest request;
    request.setManager(&manager);
    request.setKeyTemplate(keyTemplate);
    request.setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request.setKeyDerivationParameters(kdp);
    request.startRequest();
    request.waitForFinished();

    if (not IsRequestWasSuccessful(&request)) {
        qDebug() << "Error when generating key";
        throw std::runtime_error("Error when generating key");
    }

    return request.generatedKeyReference();
}
