#ifndef RADIO_H
#define RADIO_H

#include <stdint.h>

#pragma pack(push, 1)
struct radiotap {
    uint8_t version;
    uint8_t pad;
    uint16_t len;
    uint32_t present;
};
#pragma pack(pop)

#endif // RADIO_H
