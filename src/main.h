#ifndef _MAIN_H
#define _MAIN_H

// for tcp header
#include <netinet/tcp.h>
#include <netinet/udp.h>

#define NON_ATTACK 0
#define SYN_FLOOD_ATTACK 1
#define UDP_FLOOD_ATTACK 2
#define ACK_FLOOD_ATTACK 3
#define SYN_ACK_JOINT_FLOOD_ATTACK 4
#define ACK_REFLECT_ATTACK 5
#define DNS_REFLECT_ATTACK 6

#define MAX_URL_LENGTH 2048    // URL
#define MAX_IP_LENGTH 32

#define ENABLE 1
#define DISABLE 0

#define RANDOM_SOURCE_ADDRESS_REPETITION_DEFAULT 128
#define ATTACK_SOURCE_IP_DEFAULT "192.168.1.2"
#define ATTACK_SOURCE_PORT_DEFAULT 9999
#define THREAD_NUM_DEFAULT 4

#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443

/* need re-think here */
#define ACK_IP_LIST_NAME "./core_module/ack_reflect_ip_list.txt"
#define DNS_IP_LIST_NAME "./core_module/dns_reflect_ip_list.txt"

// if you want to change this name, please also edit the dns query->name size
#define DNS_QUERY_NAME_DEFAULT "github.com"

// for tcp header checksum
struct pseudo_header_tcp
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcph;
};

struct pseudo_header_udp
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
	unsigned char protocol;
	unsigned short udp_length;
	struct udphdr udph;
}

typedef struct ack_flood_thread_parameters
{
    char *daddr;
    char *saddr;
    int dport;
    int sport;
    int random_saddr;
    int rep;
} AFTP, *pAFTP;

typedef struct udp_flood_thread_parameters
{
    char *daddr;
    char *saddr;
    int dport;
    int sport;
    int random_saddr;
    int rep;
    int dp;
    int ddp;
} UFTP, *pUFTP;

typedef struct syn_flood_thread_parameters
{
    char *daddr;
    char *saddr;
    int dport;
    int sport;
    int random_saddr;
    int rep;
} SFTP, *pSFTP;


#endif