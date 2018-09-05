#include "requests.h"
#include "signverifyrequests.h"
#include "encryptdecryptrequests.h"
#include "generatestoredkeyrequests.h"
#include "createivrequests.h"
#include "cipherdecipherrequests.h"

#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/generaterandomdatarequest.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QStringList>
#include <QtCore/QLoggingCategory>
#include <QtCore/QFile>

using namespace Sailfish::Crypto;

namespace {

    void CheckSignAndVerify()
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        const auto rsaKey = GenerateStoredKeyRequests::createStoredKey(
            "MyRsaKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmRsa,
            CryptoManager::OperationSign | CryptoManager::OperationVerify,
            2048);

        QByteArray signature = SignVerifyRequests::sign(rsaKey, plainText);
        bool verified = SignVerifyRequests::verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == true);

        signature[0] = '\0'; // corrupt the signature
        verified = SignVerifyRequests::verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == false);
    }

    void EncryptAndDecryptWithAuth(const Sailfish::Crypto::Key& key,
                                   const QByteArray& plainText,
                                   const QByteArray& authCode)
    {
        qDebug() << Q_FUNC_INFO;

        const auto blockMode = CryptoManager::BlockModeGcm;
        const auto padding = CryptoManager::EncryptionPaddingNone;

        const auto iv =
            CreateIVRequests::createIV(
                key.algorithm(),
                blockMode,
                key.size());

        QByteArray authTag; // generate by crypto algorithm

        const QByteArray encrypted =
            EncryptDecryptRequests().encrypt(
                key,
                iv,
                plainText,
                blockMode,
                padding,
                authCode,
                &authTag);

        const QByteArray decrypted =
            EncryptDecryptRequests().decrypt(
                key,
                iv,
                encrypted,
                blockMode,
                padding,
                authCode,
                &authTag);

        Q_ASSERT(decrypted == plainText);
    }

    void EncryptAndDecryptWithoutAuth(const Sailfish::Crypto::Key& key,
                                      const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        const auto blockMode = CryptoManager::BlockModeCbc;
        const auto padding = CryptoManager::EncryptionPaddingNone;

        const auto iv =
            CreateIVRequests::createIV(
                key.algorithm(),
                blockMode,
                key.size());

        const QByteArray encrypted =
            EncryptDecryptRequests().encrypt(
                key,
                iv,
                plainText,
                blockMode,
                padding);

        const QByteArray decrypted =
            EncryptDecryptRequests().decrypt(
                key,
                iv,
                encrypted,
                blockMode,
                padding);

        Q_ASSERT(decrypted == plainText);
    }

    void EncryptAndDecrypt()
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        const auto aesKey = GenerateStoredKeyRequests::createStoredKey(
            "MyAesKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            256);

        EncryptAndDecryptWithAuth(aesKey, plainText, QByteArray("my_password"));
        EncryptAndDecryptWithoutAuth(aesKey, plainText);

        const auto gostKey = GenerateStoredKeyRequests::createStoredKey(
            "MyGostKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            256);

        EncryptAndDecryptWithAuth(gostKey, plainText, QByteArray("my_password"));
        EncryptAndDecryptWithoutAuth(gostKey, plainText);
    }

    void CipherAndDecipher()
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        const auto aesKey = GenerateStoredKeyRequests::createStoredKey(
            "MyAesKeyForCipher",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            256);

        const auto iv =
            CreateIVRequests::createIV(
                aesKey.algorithm(),
                CryptoManager::BlockModeCbc,
                aesKey.size());

        const auto blockMode = Sailfish::Crypto::CryptoManager::BlockModeCbc;
        const auto padding = CryptoManager::EncryptionPaddingNone;
        const auto signaturePadding = CryptoManager::SignaturePaddingNone;

        const QByteArray cipherText =
            CipherDecipherRequests::cipherText(
                aesKey,
                iv,
                plainText,
                blockMode,
                padding,
                signaturePadding);

        const QByteArray decipheredText =
            CipherDecipherRequests::decipherText(
                aesKey,
                iv,
                cipherText,
                blockMode,
                padding,
                signaturePadding);

        Q_ASSERT(plainText == decipheredText);
    }

    void DeleteStoredKey()
    {
        const QString keyName = "MyAesKeyForCipher";
        const QString collectionName = "ExampleCollection";
        const QString storageName = "org.sailfishos.secrets.plugin.storage.sqlite";

        const auto aesKey = GenerateStoredKeyRequests::createStoredKey(
            keyName,
            collectionName,
            storageName,
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            256);

        const bool keyDeleted =
            Requests::deleteStoredKey(
                keyName,
                collectionName,
                storageName);

        Q_ASSERT(keyDeleted == true);
    }

} // anonymous namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    Requests::pluginInfo();
    Requests::getRandomData();
    Requests::seedRandomGenerator();

    if (Requests::isCollectionExists()) {
        qDebug() << "Collection exists\n";

        if (Requests::deleteCollection()) {
            qDebug() << "Delete collection was successful\n";
        }
    }

    if (Requests::createCollection()) {
        qDebug() << "Create collection was successful\n";

        CheckSignAndVerify();
        EncryptAndDecrypt();
        CipherAndDecipher();
    }

    return app.exec();
}
