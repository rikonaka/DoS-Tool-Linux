#ifndef _ATTACK_ACK_REFLECT_H
#define _ATTACK_ACK_REFLECT_H

typedef struct pseudo_header
{
    // needed for checksum calculation
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcp;
} PseudoHeader;

typedef struct syn_flood_st
{
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
    size_t debug_level;
    size_t each_ip_repeat;
    pStrHeader str_header;
} SYNStruct, *pSYNStruct;

#endif