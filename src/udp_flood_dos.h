#ifndef _ATTACK_UDP_FLOOD_DOS
#define _ATTACK_UDP_FLOOD_DOS

// for UDP padding size
// make sure the size is very small
// same traffic will send more packages that make the target busy
#define PADDING_SIZE 1

typedef struct udp_struct
{
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
    size_t each_ip_repeat;
} UDPStruct, *pUDPStruct;

#endif