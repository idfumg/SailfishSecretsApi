TARGET = cryptos
target.path = /usr/bin

QT -= gui
CONFIG += c++11 link_pkgconfig warn_on debug
QMAKE_CXXFLAGS += -Wall -Wextra -Werror -pedantic -g
PKGCONFIG += sailfishcrypto sailfishsecrets

SOURCES += cryptos.cpp \
    requests.cpp \
    signverifyrequests.cpp \
    encryptdecryptrequests.cpp \
    utils.cpp \
    generatekeyrequests.cpp \
    createivrequests.cpp \
    cipherdecipherrequests.cpp \
    digestrequests.cpp

HEADERS += requests.h \
    requests.h \
    signverifyrequests.h \
    encryptdecryptrequests.h \
    utils.h \
    generatekeyrequests.h \
    createivrequests.h \
    cipherdecipherrequests.h \
    digestrequests.h

INSTALLS += target
