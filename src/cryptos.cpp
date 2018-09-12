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

    /*
      1. Signing some data with an ARSA key with specified length.
      2. Save result signature to byte array (or file).
      3. Verify that the data is not modified and authenticate it by using
         a pair data+signature.
     */
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
            2048 /*length*/);

        QByteArray signature = SignVerifyRequests::sign(rsaKey, plainText);
        bool verified = SignVerifyRequests::verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == true);

        signature[0] = '\0'; // corrupt the signature
        verified = SignVerifyRequests::verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == false);
    }

    /*
      For encrypt and decrypt some data with authentication code you must use
      AES encryption key and some password - authentication code.
      Block mode for auth encryption must be Gcm.
      You must always create an initialization vector for encryption process,
      which provide more security in compare to (ECB block mode). It must has the
      same algorithm that a our key algorithm.
      Also, you can use block modes for more security.
     */
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
                CryptoManager::DefaultCryptoPluginName,
                authCode,
                &authTag);

        const QByteArray decrypted =
            EncryptDecryptRequests().decrypt(
                key,
                iv,
                encrypted,
                blockMode,
                padding,
                CryptoManager::DefaultCryptoPluginName,
                authCode,
                &authTag);

        Q_ASSERT(decrypted == plainText);
    }

    /*
      Encrypt and decrypt some data without authentication code.
      The parameters used in this function is the same as in previous function.
     */
    void EncryptAndDecryptWithoutAuth(const Sailfish::Crypto::Key& key,
                                      const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        const auto blockMode = CryptoManager::BlockModeCbc;
        const auto padding = CryptoManager::EncryptionPaddingNone;

        const QByteArray iv =
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
                padding,
                CryptoManager::DefaultCryptoPluginName);

        /*
          If you restart program, you can decrypt by a key/collection/db name.
          Because the key data stored in the database.
         */
        const Sailfish::Crypto::Key theSameKey(
            key.name(),
            key.collectionName(),
            key.storagePluginName());

        const QByteArray decrypted =
            EncryptDecryptRequests().decrypt(
                theSameKey,
                iv,
                encrypted,
                blockMode,
                padding,
                CryptoManager::DefaultCryptoPluginName);

        Q_ASSERT(decrypted == plainText);
    }

    void EncryptAndDecryptWithoutAuthGost(const Sailfish::Crypto::Key&,
                                          const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        const auto key = GenerateStoredKeyRequests::createStoredKey(
            "MyGostKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmGost,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            256 /*key length: 128, 192, 256 for AES*/);

        const auto blockMode = CryptoManager::BlockModeCbc;
        const auto padding = CryptoManager::EncryptionPaddingNone;

        // const QByteArray iv =
        //     CreateIVRequests::createIV(
        //         key.algorithm(),
        //         blockMode,
        //         key.size());

        const QByteArray encrypted =
            EncryptDecryptRequests().encrypt(
                key,
                QByteArray(),
                plainText,
                blockMode,
                padding,
                "org.sailfishos.plugin.encryption.gost");

        const QByteArray decrypted =
            EncryptDecryptRequests().decrypt(
                key,
                QByteArray(),
                encrypted,
                blockMode,
                padding,
                "org.sailfishos.plugin.encryption.gost");

        Q_ASSERT(decrypted == plainText);
    }

    /*
      It function prepare data to use AES encryption and decryption.
     */
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
            256 /*key length: 128, 192, 256 for AES*/);

        // EncryptAndDecryptWithAuth(aesKey, plainText, QByteArray("my_password"));
        // EncryptAndDecryptWithoutAuth(aesKey, plainText);
        EncryptAndDecryptWithoutAuthGost(aesKey, plainText);
    }

    /*
      sailfish secrets provide a mechanism for stream encrypting and decrypting
      process wich names as cipher and decipher with a AES algorithm.
      You can specify block mode, padding, signature padding for your needs of security.
      This funtion provide some abstraction, which feed plainText data to sailifsh secrets
      by chunks in CipherDecipherrequests class functions. In real application you can
      obtain information by network or from file by chunks and feed this data by chunks to
      sailfish secrets cipher/decipher mechanism.
      For use this type of encryption you must use firstly InitializeCipher request
      to initialize mechanism. Then you must use UpdateCipher to feed it some data chunks.
      When all data will be feed you must send requests with FinalizeCipher type.
      Decryption process has the smae algorithm.
      All this done in cipherdechiperrequests.cpp.
     */
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

    /*
      Function for deleting stored secret key in collection.
     */
    void DeleteStoredKey()
    {
        const QString keyName = "MyAesKeyForCipherForDeleting";
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

/*
  Before working with keys and encryptions you must create some collection with
  a sailfish secrets api.
  It has functions to check if collection exists, or delete some collection, or
  create new custom collection with will be contains some secrets keys.
 */
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    /*
      Print plugin names which your system provides.
      It will be storage plugins, encrypted storage plugins, encryption plugins, etc.
     */
    Requests::pluginInfo();

    /*
      This requests uses for generate some random data.
      It uses /dev/urandom data generator, but you can specified or define yours.
      It can be used for seeding PRNG in future for generating more secure keys.
     */
    // Requests::getRandomData();

    /*
      This function seed PRNG with some data which your got from lastly.
      For testing purposes it sends some default values, but in real application your
      must specify true random data for real security.
     */
    // Requests::seedRandomGenerator();

    if (Requests::isCollectionExists()) {
        qDebug() << "Collection exists\n";

        if (Requests::deleteCollection()) {
            qDebug() << "Delete collection was successful\n";
        }
    }

    if (Requests::createCollection()) {
        qDebug() << "Create collection was successful\n";

        // CheckSignAndVerify();
        EncryptAndDecrypt();
        // CipherAndDecipher();
        // DeleteStoredKey();
    }

    return app.exec();
}
