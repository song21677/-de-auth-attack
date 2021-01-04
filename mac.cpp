#include "mac.h"

Mac::Mac(const std::string r) {
    unsigned int a, b, c, d, e, f;
    int res = sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
    if (res != SIZE) {
        fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
        return;
    }
    mac[0] = a;
    mac[1] = b;
    mac[2] = c;
    mac[3] = d;
    mac[4] = e;
    mac[5] = f;
}

