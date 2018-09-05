#include "requests.h"
#include "utils.h"

#include <Sailfish/Crypto/cipherrequest.h>
#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/deletestoredkeyrequest.h>
#include <Sailfish/Crypto/generateinitializationvectorrequest.h>
#include <Sailfish/Crypto/generaterandomdatarequest.h>
#include <Sailfish/Crypto/generatestoredkeyrequest.h>
#include <Sailfish/Crypto/seedrandomdatageneratorrequest.h>
#include <Sailfish/Crypto/storedkeyrequest.h>

#include <Sailfish/Secrets/collectionnamesrequest.h>
#include <Sailfish/Secrets/createcollectionrequest.h>
#include <Sailfish/Secrets/deletecollectionrequest.h>
#include <Sailfish/Secrets/plugininforequest.h>
#include <Sailfish/Secrets/secretmanager.h>

#include <QtCore/QDebug>

using namespace Sailfish::Crypto;
using namespace Sailfish::Secrets;

namespace {

    const QString KEY_NAME = QStringLiteral("ExampleKey");
    const QString COLLECTION_NAME = QLatin1String("ExampleCollection");
    const QString DB_NAME = QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite");
    const Key::Identifier keyIdentifier(KEY_NAME, COLLECTION_NAME, DB_NAME);

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

/*
  Request for getting random data.
  In this function we setup request, give it a random data length and start it.
  We trying to work asynchronously, so we working though callback mechanism.
 */
void Requests::getRandomData()
{
    qDebug() << Q_FUNC_INFO;

    const std::size_t RANDOM_DATA_LENGTH = 128;

    CryptoManager manager;
    GenerateRandomDataRequest* const request = new GenerateRandomDataRequest;
    request->setManager(&manager);
    request->setCryptoPluginName(CryptoManager::DefaultCryptoPluginName);
    request->setCsprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName);
    request->setNumberBytes(RANDOM_DATA_LENGTH);
    request->startRequest();
    connect(request, &GenerateRandomDataRequest::statusChanged, [request] () {
        if (IsRequestWasSuccessful(request)) {
            qDebug() << request->generatedData();
        }

        request->deleteLater();
    });
}

void Requests::seedRandomGenerator()
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

bool Requests::isCollectionExists()
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

bool Requests::deleteCollection()
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

bool Requests::createCollection()
{
    qDebug() << Q_FUNC_INFO;

    SecretManager manager;
    CreateCollectionRequest* const request = new CreateCollectionRequest;
    request->setManager(&manager);
    request->setEncryptionPluginName("org.sailfishos.secrets.plugin.encryption.openssl");
    request->setStoragePluginName(DB_NAME);
    request->setCollectionName(COLLECTION_NAME);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    return IsRequestWasSuccessful(request);
}

Sailfish::Crypto::Key Requests::getStoredKey()
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

void Requests::pluginInfo()
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

bool Requests::deleteStoredKey(const QString& keyName,
                               const QString& collectionName,
                               const QString& dbName)
{
    qDebug() << Q_FUNC_INFO;

    CryptoManager manager;
    DeleteStoredKeyRequest* const request = new DeleteStoredKeyRequest;
    request->setIdentifier(Key::Identifier(keyName, collectionName, dbName));
    request->setManager(&manager);
    request->startRequest();
    request->waitForFinished();
    request->deleteLater();

    return IsRequestWasSuccessful(request);
}
