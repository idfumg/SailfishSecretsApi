#pragma once

#include <Sailfish/Crypto/key.h>

class SignVerifyRequests : public QObject {
    Q_OBJECT

public:
    static QByteArray sign(const Sailfish::Crypto::Key& key,
                           const QByteArray& data);
    static bool verify(const Sailfish::Crypto::Key& key,
                       const QByteArray& data,
                       const QByteArray& signature);
};
