#ifndef _ATTACK_SYN_FLOOD_DOS_H
#define _ATTACK_SYN_FLOOD_DOS_H
//#include <sys/socket.h>
// For exit(0);
//#include <netinet/tcp.h>
// Provides declarations for ip header
//#include <netinet/ip.h>
//#include <netinet/in.h>
//#include <arpa/inet.h>
//#include "../main.h"

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
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
    size_t each_ip_repeat;
} SYNStruct, *pSYNStruct;

#endif