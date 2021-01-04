#ifndef AUTH_H
#define AUTH_H

#include <stdint.h>
#include "radio.h"
#include "dot11.h"
#include "mac.h"

#pragma pack(push, 1)
struct authentication : dot11{
    Mac dest;
    Mac source;
    Mac bssid;
    uint16_t seq;
};
#pragma pack(pop)


#pragma pack(push, 1)
struct auth_wireless {
    uint16_t auth_algorithm;
    uint16_t auth_seq;
    uint16_t status;
    uint8_t tag_num;
    uint8_t tag_len;
    uint8_t oui[3];
    uint8_t vendor[6];
};
#pragma pack(pop)

#pragma pack(push, 1)
struct authpacket {
    struct radiotap radio;
    struct authentication auth;
    struct auth_wireless wireless;
};
#pragma pack(pop)

#endif // AUTH_H
