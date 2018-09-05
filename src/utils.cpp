#include <Sailfish/Crypto/cryptomanager.h>
#include <Sailfish/Crypto/request.h>
#include <Sailfish/Secrets/secretmanager.h>
#include <Sailfish/Secrets/request.h>

#include <QtCore/QDebug>

bool IsRequestWasSuccessful(Sailfish::Crypto::Request* request)
{
    if (request->status() != Sailfish::Crypto::Request::Finished or
        request->result().code() != Sailfish::Crypto::Result::Succeeded)
        {
            qDebug() << "\n\n";
            qDebug() << request->status();
            qDebug() << request->result().code();
            qDebug() << request->result().errorMessage();
        }

    return
        request->status() == Sailfish::Crypto::Request::Finished and
        request->result().code() == Sailfish::Crypto::Result::Succeeded;
}

bool IsRequestWasSuccessful(Sailfish::Secrets::Request* request)
{
    if (request->status() != Sailfish::Secrets::Request::Finished or
        request->result().code() != Sailfish::Secrets::Result::Succeeded)
        {
            qDebug() << "\n\n";
            qDebug() << request->status();
            qDebug() << request->result().code();
            qDebug() << request->result().errorMessage();
        }

    return
        request->status() == Sailfish::Secrets::Request::Finished and
        request->result().code() == Sailfish::Secrets::Result::Succeeded;
}
