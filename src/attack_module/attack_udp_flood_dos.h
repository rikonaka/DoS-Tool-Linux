#ifndef _ATTACK_UDP_FLOOD_DOS
#define _ATTACK_UDP_FLOOD_DOS

// for UDP padding size
// make sure the size is very small
// same traffic will send more packages that make the target busy
#define PADDING_SIZE 1

typedef struct udp_struct
{
    int loop;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
} UDPStruct, *pUDPStruct;

#endif