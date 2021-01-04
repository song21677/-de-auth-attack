#include "header.h"

void parse_dev()
{
    system("iw dev > devname.txt");

    char buffer[200];

    FILE *fp = fopen("/root/thread/build/devname.txt", "r");

    char word[] = "Interface";
    char* ptr = nullptr;

    int i=0;

    if (fp != NULL) {
        while ( !feof(fp) ) {
            fgets(buffer, sizeof(buffer), fp);
            ptr = strstr(buffer, word);
            if (ptr != NULL) break;
        }
    }

    strcpy(dev,  ptr+10);

    while (1) {

        if (dev[i] == '\n') {
            dev[i] = 0;
            break;
        }
        i++;
    }
}
