#ifndef MAC
#define MAC

#include <cstdint>
#include <cstring>
#include <string>

struct Mac{
    static const int SIZE = 6;

    Mac() {}
    Mac(std::string r);

protected:
    uint8_t mac[SIZE];
};

#endif

