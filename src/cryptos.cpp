#include "requests.h"
#include "signverifyrequests.h"
#include "encryptdecryptrequests.h"
#include "generatekeyrequests.h"
#include "createivrequests.h"
#include "cipherdecipherrequests.h"
#include "digestrequests.h"

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
      В данных примерах используются специальные функции и классы, которые являются
      обертками над более низкоуровневым интерфейсом sailfish secrets. Они сделаны для
      удобства и не обязательны для использования.
      Все детали реализации расположены в соответсвующих файлах/классах, расположенных
      в этом же проекте.
     */

    /*
      Для подписи реализованы два алгоритма RSA и Gost.
      Чтобы создать подпись, необходимо сначала создать ключ, указав в качестве операций
      Sign & Verify, которые будут выполняться с этим ключом, функция хэширования,
      алгоритм шифрования и padding по-умолчанию. Также, необходимо указать плагин,
      с помощью которого будет осуществляться работа с этим ключом (реализованы отдельно
      от sailfish secrets). Реализованы два плагина:
      1. DefaultCryptoPluginName
      2. org.sailfishos.plugin.encryption.gost

      При создании хранимого ключа, его данные будут автоматически сохранены в базу данных
      и не будут передаваться по сети.
      Эти данные не появятся в адресном пространстве данного процесса, который использует
      AIP sailfish secrets.
      Чтобы создать хранимый ключ, необходимо заранее создать коллекцию, к которой
      данный ключ будет храниться.
      В функции main() проверяется, была создана коллекция, и если нет, то она создается.

      Далее, необходимо использовать функцию sign для создания подписи.
      В него необходимо передать данные, которые нужно подписать, ключ,
      имя плагина, который был указан при создании ключа, тот же самый padding и
      функцию хэширования (подпись не будет применяться сразу для всего объема данных,
      а сначала будет выполнено создания хэша, который будет идентифицировать данные,
      а затем будет подписан сам ключ).

      Функция подписи вернет подпись для переданных данных.
      Эта подпись понадобиться для того, чтобы проверить подписанные данные в будущем.
      Чтобы проверить подпись, необходимо в функцию verify передать собственно данные,
      цифровую подпись, которая получилась на предыдущем этапе, имя плагина, padding,
      функция хэширования.

      Проверка будет использовать публичный ключ и, если будет пройдена успешно, вернет
      true.
     */
    void CheckSignAndVerify()
    {
        qDebug() << Q_FUNC_INFO;

        constexpr auto plainText = "The quick brown fox jumps over the lazy dog";
        const auto pluginName = CryptoManager::DefaultCryptoPluginName;
        constexpr auto padding = Sailfish::Crypto::CryptoManager::SignaturePaddingNone;
        constexpr auto digestFunction = CryptoManager::DigestSha512;
        constexpr auto keyLength = 2048;

        const auto rsaKey = GenerateKeyRequests::createStoredKey(
            "MyRsaKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmRsa,
            CryptoManager::OperationSign | CryptoManager::OperationVerify,
            digestFunction,
            keyLength,
            pluginName);

        QByteArray signature =
            SignVerifyRequests::sign(
                rsaKey,
                plainText,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(not signature.isEmpty());

        bool verified =
            SignVerifyRequests::verify(
                rsaKey,
                plainText,
                signature,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(verified == true);

        signature[0] = '\0'; // corrupt the signature
        verified =
            SignVerifyRequests::verify(
                rsaKey,
                plainText,
                signature,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(verified == false);
    }

    /*
      Здесь мы используем другое имя плагина и функцию хэширования, и функцию шифрования.
      Также обратить внимания, что длина ключа должна быть равна 256.
     */
    void CheckSignAndVerifyGost()
    {
        qDebug() << Q_FUNC_INFO;

        constexpr auto pluginName = "org.sailfishos.plugin.encryption.gost";
        constexpr auto digestFunction = Sailfish::Crypto::CryptoManager::DigestGost_2012_256;
        constexpr auto keyLength = 256;
        constexpr auto padding = Sailfish::Crypto::CryptoManager::SignaturePaddingNone;
        constexpr auto plainText = "The quick brown fox jumps over the lazy dog";

        const auto key = GenerateKeyRequests::createStoredKey(
            "MyGostKeyForSign",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmGost,
            CryptoManager::OperationSign | CryptoManager::OperationVerify,
            digestFunction,
            keyLength,
            pluginName);

        QByteArray signature =
            SignVerifyRequests::sign(
                key,
                plainText,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(not signature.isEmpty());

        bool verified =
            SignVerifyRequests::verify(
                key,
                plainText,
                signature,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(verified == true);

        signature[0] = '\0'; // corrupt the signature

        verified =
            SignVerifyRequests::verify(
                key,
                plainText,
                signature,
                pluginName,
                padding,
                digestFunction);

        Q_ASSERT(verified == false);
    }

    /*
      Для того, чтобы зашифровать и расшифровать данные с ипользованием ключа аутентификации
      необходимо использовать алгоритм AES и пароль.
      Ключ должен быть уже создан с поддержкой операции Encrypt/Decrypt.
      Для AES с шифрованием с использованием кода, необходимо использовать блочный режим
      Gcm и padding None.
      Также, чтобы использовать AES, необходимо указать стандартный крипто плагин, в
      котором он реализован.
      Чтобы использовать данный вид шифрования, необходимо создать вектор инициализации,
      который будет использован функцией шифрования в качестве первоначального блока,
      который предоставляет больший уровень надежности в сравнении с обычным ECB блочным
      режимом.
      Перед тем, как использовать функции шифрования и создании вектора инициализации,
      желательно сидить генератор случайных чисел с помощью энтропии, которое выполняется
      в функции main. Это необходмио, чтобы алгоритмы шифрования использовали более
      надежные и случайные данные для своей работы, чтобы надежность ключа была
      максимальной.
     */
    void EncryptAndDecryptWithAuth(const Sailfish::Crypto::Key& key,
                                   const QByteArray& plainText,
                                   const QByteArray& authCode)
    {
        qDebug() << Q_FUNC_INFO;

        constexpr auto blockMode = CryptoManager::BlockModeGcm;
        constexpr auto padding = CryptoManager::EncryptionPaddingNone;

        const auto iv =
            CreateIVRequests::createIV(
                key.algorithm(),
                blockMode,
                key.size(),
                CryptoManager::DefaultCryptoPluginName);

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
      Шифрование без использования кода авторизации.
      Здесь используются те же параметры, что и в функции выше, которая работает с кодом
      авторизации, только без него.
     */
    void EncryptAndDecryptWithoutAuth(const Sailfish::Crypto::Key& key,
                                      const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        constexpr auto blockMode = CryptoManager::BlockModeCbc;
        constexpr auto padding = CryptoManager::EncryptionPaddingNone;

        const QByteArray iv =
            CreateIVRequests::createIV(
                key.algorithm(),
                blockMode,
                key.size(),
                CryptoManager::DefaultCryptoPluginName);

        const QByteArray encrypted =
            EncryptDecryptRequests().encrypt(
                key,
                iv,
                plainText,
                blockMode,
                padding,
                CryptoManager::DefaultCryptoPluginName);

        /*
          Создание данного нового ключа приведено в качестве примера, который говорит о том,
          что созданный и созхраненный в базе данных ключ, может использоваться повторно,
          даже после того, как программа была завершена. Для этого, нужно только знать
          имя ключа, имя коллекции, в которой он хранится, а также имя плагина, который
          использовался для создания ключа.
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

    /*
      Пока алгоритм шифрования Гост не использует шифрование с  использованием ключа
      аутентификации, все параметры те же, что и в предыдущих функциях, за исключением
      имени плагина, алгоритма шифрования, наименования функции хэширования.
     */
    void EncryptAndDecryptWithoutAuthGost(const Sailfish::Crypto::Key&,
                                          const QByteArray& plainText)
    {
        qDebug() << Q_FUNC_INFO;

        constexpr auto blockMode = CryptoManager::BlockModeOfb;
        constexpr auto padding = CryptoManager::EncryptionPaddingNone;
        constexpr auto pluginName = "org.sailfishos.plugin.encryption.gost";

        /*
          Также можно создать ключ, который не хранится в базе данных, а будет полностью
          передан в адресное пространства текущего процесса.
         */
        // const auto key = GenerateKeyRequests::createKey(
        //     CryptoManager::AlgorithmGost,
        //     CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
        //     Sailfish::Crypto::CryptoManager::DigestGost_2012_256,
        //     256,
        //     pluginName);

        const auto key = GenerateKeyRequests::createStoredKey(
            "MyGostKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmGost,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            Sailfish::Crypto::CryptoManager::DigestGost_2012_256,
            256,
            pluginName);

        const QByteArray iv =
            CreateIVRequests::createIV(
                key.algorithm(),
                blockMode,
                key.size(),
                pluginName);

        const QByteArray encrypted =
            EncryptDecryptRequests().encrypt(
                key,
                iv,
                plainText,
                blockMode,
                padding,
                pluginName);

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
                pluginName);

        Q_ASSERT(decrypted == plainText);
    }

    /*
      Функция, которыя вызывается различные функции для шифрования и расшифрования
      с применением различных алгоритмов (AES & Gost).
     */
    void EncryptAndDecrypt()
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        const auto aesKey = GenerateKeyRequests::createStoredKey(
            "MyAesKey",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            Sailfish::Crypto::CryptoManager::DigestSha512,
            256 /*key length: 128, 192, 256 for AES*/,
            CryptoManager::DefaultCryptoPluginName);

        EncryptAndDecryptWithAuth(aesKey, plainText, QByteArray("my_password"));
        EncryptAndDecryptWithoutAuth(aesKey, plainText);
        EncryptAndDecryptWithoutAuthGost(aesKey, plainText);
    }

    /*
      Для алгоритма AES предоставляется специальный механзм поточного шифрования, при
      котором можно пересылать на зашифровку данные порциями, например, из файла или
      данных, приходящих по сети.
      Чтобы использовать данный механизм, необходимо сначала инициализировать
      механизм, с помощью запрос InitializeCipher. Затем, необходимо передавать ему
      данные с помощью UpdateCipher. Когда все необходимые данные будут переданы,
      необходимо завершить шифрование используя запрос FinalizeCipher.
      Алгоритм расшифрования имеет тот же алгоритм.
     */
    void CipherAndDecipher()
    {
        qDebug() << Q_FUNC_INFO;

        const QByteArray plainText = "The quick brown fox jumps over the lazy dog";

        const auto aesKey = GenerateKeyRequests::createStoredKey(
            "MyAesKeyForCipher",
            "ExampleCollection",
            "org.sailfishos.secrets.plugin.storage.sqlite",
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            Sailfish::Crypto::CryptoManager::DigestSha512,
            256,
            CryptoManager::DefaultCryptoPluginName);

        const auto iv =
            CreateIVRequests::createIV(
                aesKey.algorithm(),
                CryptoManager::BlockModeCbc,
                aesKey.size(),
                CryptoManager::DefaultCryptoPluginName);

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
      Функция, которая показывает способ для удалния из коллекции сохраненного ключа.
      Сначала он создается, потом удаляется.
     */
    void DeleteStoredKey()
    {
        const QString keyName = "MyAesKeyForCipherForDeleting";
        const QString collectionName = "ExampleCollection";
        const QString storageName = "org.sailfishos.secrets.plugin.storage.sqlite";

        const auto aesKey = GenerateKeyRequests::createStoredKey(
            keyName,
            collectionName,
            storageName,
            CryptoManager::AlgorithmAes,
            CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
            Sailfish::Crypto::CryptoManager::DigestSha512,
            256,
            CryptoManager::DefaultCryptoPluginName);

        const bool keyDeleted =
            Requests::deleteStoredKey(
                keyName,
                collectionName,
                storageName);

        Q_ASSERT(keyDeleted == true);
    }

    /*
      Функция, которая показывает, как использовать механизм генерации хэша по переданным
      произвольным данным с помощью алгоритма Gost.
     */
    void DigestGost()
    {
        constexpr auto data = "The quick brown fox jumps over the lazy dog";
        constexpr auto pluginName = "org.sailfishos.plugin.encryption.gost";

        const QByteArray digest =
            DigestRequests::digest(
                data,
                CryptoManager::SignaturePaddingNone,
                CryptoManager::DigestGost_2012_256,
                pluginName);

        Q_ASSERT(digest.size() == 32);
    }

} // anonymous namespace

/*
  Перед тем, как начать работу с ключами шифрования, необходимо создать специальные
  коллекции для их хранения в базе данных.
  Приведены примеры функции для создания коллекции, удаления коллекции и проверки на
  существование уже созданной коллекции.
 */
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);

    /*
      Печатает список плагинов ,которые установлены в системе.
     */
    Requests::pluginInfo();

    /*
      Запрос, который возвращает случайные данные.
      Эти данные могут быть использованы для сидирование PRNG для генерации более
      надежных секретных ключей.
     */
    Requests::getRandomData();

    /*
      Эта функция инициализирует генератор случайных чисел с помощью полученных ранее
      случайных данных, на основе которых он будет генерировать данные.
     */
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
        CheckSignAndVerifyGost();
        EncryptAndDecrypt();
        CipherAndDecipher();
        DeleteStoredKey();
        DigestGost();
    }

    return app.exec();
}
