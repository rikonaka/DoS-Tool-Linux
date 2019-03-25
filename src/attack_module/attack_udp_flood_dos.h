#ifndef _ATTACK_UDP_FLOOD_DOS
#define _ATTACK_UDP_FLOOD_DOS

#define PADDING_SIZE 1
#define N_LOOP 10
#define U_WAITING 100000

typedef struct udp_struct
{
    int loop;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
} UDPStruct, *pUDPStruct;

#endif