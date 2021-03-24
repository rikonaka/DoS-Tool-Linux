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
#define HTTP_FLOOD_ATTACK 5

#define MAX_URL_LENGTH 2048    // URL
#define MAX_IP_LENGTH 32
#define MAX_PATH_LENGTH 128

#define ENABLE 1
#define DISABLE 0
#define HTTP 0
#define HTTPS 1

#ifdef DEBUG
#define RANDOM_SOURCE_ADDRESS_REPETITION_DEFAULT 128
#define ATTACK_SOURCE_IP_DEFAULT "192.168.1.2"
#define ATTACK_SOURCE_PORT_DEFAULT 9999
#define THREAD_NUM_DEFAULT 1
#define HTTP_FLOOD_ATTACK_DEFAULT HTTP // http
#define PACKET_NUMBER_DEFAULT 4
#else
#define RANDOM_SOURCE_ADDRESS_REPETITION_DEFAULT 128
#define ATTACK_SOURCE_IP_DEFAULT "192.168.1.2"
#define ATTACK_SOURCE_PORT_DEFAULT 9999
#define THREAD_NUM_DEFAULT 4
#define HTTP_FLOOD_ATTACK_DEFAULT HTTP // http
#define PACKET_NUMBER_DEFAULT __INT32_MAX__
#endif


#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443

#define PADDING_SIZE 4; // 4B

// for tcp header checksum
struct pseudo_header_tcp
{
	unsigned int saddr;
	unsigned int daddr;
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
};

typedef struct ack_flood_thread_parameters
{
    char *daddr;
    int dport;
    char *saddr;
    int sport;
    int rdsrc;
    int rt;
    unsigned int pn;
} AFTP, *pAFTP;

typedef struct udp_flood_thread_parameters
{
    char *daddr;
    char *saddr;
    int dport;
    int sport;
    int rdsrc;
    int rep;
    int ddps;
    int ddpp;
    unsigned int pn;
} UFTP, *pUFTP;

typedef struct syn_flood_thread_parameters
{
    char *daddr;
    int dport;
    char *saddr;
    int sport;
    int rdsrc;
    int rt;
    unsigned int pn;
} SFTP, *pSFTP;

typedef struct http_flood_thread_parameters
{
    char *url;
    int port;
    char *request;
    int https;
    unsigned int pn;
} HFTP, *pHFTP;

extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

extern char *randip(char **buff);
extern int randport(void);
extern unsigned short checksum(unsigned short *ptr, int hlen, char *data, int dlen);

#endif