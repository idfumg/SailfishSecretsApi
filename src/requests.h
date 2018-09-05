#pragma once

#include <Sailfish/Crypto/key.h>

namespace Sailfish {
    namespace Crypto {
        class Request;
    }
}

class Requests : public QObject {
    Q_OBJECT

public:
    static void getRandomData();
    static void seedRandomGenerator();
    static bool isCollectionExists();
    static bool deleteCollection();
    static bool createCollection();
    static Sailfish::Crypto::Key getStoredKey();
    static void pluginInfo();
    static bool deleteStoredKey(const QString& keyName,
                                const QString& collectionName,
                                const QString& dbName);
};
