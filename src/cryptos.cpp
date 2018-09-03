#include "requests.h"

#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/generaterandomdatarequest.h>

#include <QtCore/QCoreApplication>
#include <QtCore/QDebug>
#include <QtCore/QStringList>
#include <QtCore/QLoggingCategory>
#include <QtCore/QFile>

using namespace Sailfish::Crypto;

namespace {

    // void TryToEncryptDecrypt(const Requests& requests,
    //                          const Sailfish::Crypto::Key& key,
    //                          const QByteArray& iv,
    //                          const QByteArray& plainText)
    // {
    //     qDebug() << Q_FUNC_INFO;



    //     // you can read key from db if it was stored
    //     // how its working - is super secret!
    //     // const auto storedKey = requests.getStoredKey();
    //     // const auto cipherTextFromStored = requests.encrypt(storedKey, iv, plainText);
    //     // const auto decryptedFromStored = requests.decrypt(storedKey, iv, cipherText);
    //     // qDebug() << "decryptedFromStored = " << decryptedFromStored;
    //     // Q_ASSERT(plainText == decryptedFromStored);
    // }

} // anonymous namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    Requests requests;

    requests.pluginInfo();
    requests.getRandomData();
    requests.seedRandomGenerator();

    if (requests.isCollectionExists()) {
        qDebug() << "Collection exists\n";

        if (requests.deleteCollection()) {
            qDebug() << "Delete collection was successful\n";
        }
    }

    if (requests.createCollection()) {
        qDebug() << "Create collection was successful\n";

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        /*
          Symmetric key
         */
        const auto key = requests.createStoredKey(requests.createTemplateKey());

        /*
          Initialization vector
         */
        const auto iv = requests.createIV(key);

        /*
          Encrypt/Decrypt
         */
        const QByteArray encryptedText = requests.encrypt(key, iv, plainText);
        const QByteArray decryptedText = requests.decrypt(key, iv, encryptedText);
        Q_ASSERT(plainText == decryptedText);

        /*
          Cipher/Decipher
         */
        const QByteArray cipherText = requests.cipherText(key, iv, plainText);
        const QByteArray decipheredText = requests.decipherText(key, iv, cipherText);
        Q_ASSERT(cipherText == encryptedText);
        Q_ASSERT(plainText == decipheredText);

        /*
          Encrypt/Decrypt with authentication code
         */
        const QByteArray authCode("my_password");
        const auto ivForAuth = requests.createIVForAuth(key);
        QByteArray authTag;
        const QByteArray encrypted =
            requests.encryptWithAuth(key, ivForAuth, plainText, authCode, authTag);
        const QByteArray decrypted =
            requests.decryptWithAuth(key, ivForAuth, encrypted, authCode, authTag);
        Q_ASSERT(decrypted == plainText);

        /*
          Delete existing key
         */
        bool keyDeleted = requests.deleteStoredKey();
        Q_ASSERT(keyDeleted == true);

        /*
          Encrypt/Decrypt with GOST
         */
        const auto keyGOST = requests.createStoredKey(requests.createTemplateKey());
        const QByteArray encryptedText_ = requests.encrypt(keyGOST, iv, plainText);
        const QByteArray decryptedText_ = requests.decrypt(keyGOST, iv, encryptedText_);
        Q_ASSERT(plainText == decryptedText_);

        /*
          Delete existing key
         */
        keyDeleted = requests.deleteStoredKey();
        Q_ASSERT(keyDeleted == true);

        /*
          Sign/Verify
         */
        const auto rsaKey = requests.createStoredKeyRSA();
        QByteArray signature = requests.sign(rsaKey, plainText);
        bool verified = requests.verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == true);

        signature[0] = '\0'; // corrupt the signature
        verified = requests.verify(rsaKey, plainText, signature);
        Q_ASSERT(verified == false);
    }

    return app.exec();
}
