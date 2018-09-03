TARGET = cryptos
target.path = /usr/bin

QT -= gui
CONFIG += c++11 link_pkgconfig warn_on debug
QMAKE_CXXFLAGS += -Wall -Wextra -Werror -pedantic
PKGCONFIG += sailfishcrypto sailfishsecrets

SOURCES += cryptos.cpp requests.cpp
HEADERS += requests.h

INSTALLS += target
