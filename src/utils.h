#pragma once

namespace Sailfish {
    namespace Crypto {
        class Request;
    }
    namespace Secrets {
        class Request;
    }
}

bool IsRequestWasSuccessful(Sailfish::Crypto::Request* request);
bool IsRequestWasSuccessful(Sailfish::Secrets::Request* request);
