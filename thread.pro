TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += \
     -lpcap \
     -lpthread


SOURCES += \
        mac.cpp \
        main.cpp

HEADERS += \
    assoc.h \
    auth.h \
    deauth.h \
    dot11.h \
    mac.h \
    radio.h

DISTFILES += \
    build/parsed_airodump-01.csv \
    parsed_airodump-01.csv

DESTDIR = $${PWD}/build
