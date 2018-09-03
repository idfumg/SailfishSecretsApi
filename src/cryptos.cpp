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

    void TryToEncryptDecrypt(const Requests& requests,
                             const Sailfish::Crypto::Key& key,
                             const QByteArray& iv,
                             const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray encryptedText = requests.encrypt(key, iv, plainText);
        const QByteArray decryptedText = requests.decrypt(key, iv, encryptedText);
        Q_ASSERT(plainText == decryptedText);

        const QByteArray cipherText = requests.cipherText(key, iv, plainText);
        const QByteArray decipheredText = requests.decipherText(key, iv, cipherText);
        Q_ASSERT(cipherText == encryptedText);
        Q_ASSERT(plainText == decipheredText);

        const QByteArray signed_ = requests.sign(key, plainText);

        // you can read key from db if it was stored
        // how its working - is super secret!
        // const auto storedKey = requests.getStoredKey();
        // const auto cipherTextFromStored = requests.encrypt(storedKey, iv, plainText);
        // const auto decryptedFromStored = requests.decrypt(storedKey, iv, cipherText);
        // qDebug() << "decryptedFromStored = " << decryptedFromStored;
        // Q_ASSERT(plainText == decryptedFromStored);
    }

    void TryToEncrypt(const Requests& requests)
    {
        if (requests.isCollectionExists()) {
            qDebug() << "Collection exists\n";

            if (requests.deleteCollection()) {
                qDebug() << "Delete collection was successful\n";
            }
        }

        if (requests.createCollection()) {
            qDebug() << "Create collection was successful\n";

            const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

            const auto key = requests.createStoredKey(requests.createTemplateKey());
            const auto iv = requests.createIV(key);

            TryToEncryptDecrypt(requests, key, iv, plainText);

            if (not requests.deleteStoredKey()) {
                qDebug() << "Cannot delete stored key";
            }
            else {
                qDebug() << "Stored key was removed";
            }
        }
    }

} // anonymous namespace

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    Requests requests;

    requests.pluginInfo();

    TryToEncrypt(requests);

    requests.getRandomData();
    requests.seedRandomGenerator();

    return app.exec();
}
