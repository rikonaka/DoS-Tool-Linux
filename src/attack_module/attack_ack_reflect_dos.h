#ifndef _ATTACK_ACK_REFLECT_DOS_H
#define _ATTACK_ACK_REFLECT_DOS_H

typedef struct pseudo_header
{
    // Needed for checksum calculation
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} PseudoHeader;

typedef struct syn_struct
{
    int loop;
    char *src_ip;
    char *dst_ip;
    int src_port;
    int dst_port;
    int debug_level;
    int each_ip_repeat;
} SYNStruct, *pSYNStruct;

#endif