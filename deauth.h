#ifndef HEADER_H
#define HEADER_H

#include <stdint.h>
#include "radio.h"
#include "dot11.h"
#include "mac.h"

#pragma pack(push, 1)
struct deauthentication : dot11 {
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauth_wireless {
    uint16_t reason;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct deauthpacket {
    struct radiotap radio;
    struct deauthentication deauth;
    struct deauth_wireless wireless;
};
#pragma pack(pop)

//void parse_dev();

#endif
