#ifndef ASSOC_H
#define ASSOC_H

#include <stdint.h>
#include "radio.h"
#include "dot11.h"
#include "mac.h"

#pragma pack(push, 1)
struct association : dot11 {
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct assoc_wireless {
    uint16_t cap;
    uint16_t li;
    uint8_t ssid[2];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct assocpacket {
    struct radiotap radio;
    struct association assoc;
    struct assoc_wireless wireles;
};
#pragma pack(pop)

#endif // ASSOC_H
