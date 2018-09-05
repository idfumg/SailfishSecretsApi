TARGET = cryptos
target.path = /usr/bin

QT -= gui
CONFIG += c++11 link_pkgconfig warn_on debug
QMAKE_CXXFLAGS += -Wall -Wextra -Werror -pedantic
PKGCONFIG += sailfishcrypto sailfishsecrets

SOURCES += cryptos.cpp \
    requests.cpp \
    signverifyrequests.cpp \
    encryptdecryptrequests.cpp \
    utils.cpp \
    generatestoredkeyrequests.cpp \
    createivrequests.cpp \
    cipherdecipherrequests.cpp

HEADERS += requests.h \
    requests.h \
    signverifyrequests.h \
    encryptdecryptrequests.h \
    utils.h \
    generatestoredkeyrequests.h \
    createivrequests.h \
    cipherdecipherrequests.h

INSTALLS += target
