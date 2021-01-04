#ifndef DOT11_H
#define DOT11_H

#include <stdint.h>

#pragma pack(push, 1)
struct dot11 {
    uint16_t fc;
    uint16_t dur;
};
#pragma pack(pop)

#endif // DOT11_H
