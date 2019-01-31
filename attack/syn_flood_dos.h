#ifndef _SYN_FLOOD_DOS_H
#define _SYN_FLOOD_DOS_H
#include <sys/socket.h>
// For exit(0);
#include <netinet/tcp.h>
// Provides declarations for ip header
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "../main.h"

#define DISABLE_SIP 0
#define ENABLE_SIP 1
#define SIP_ADDRESS "192.168.1.99"
#define SIP_PORT 9999

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
} SYNStruct, *pSYNStruct;

#endif