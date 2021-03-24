
#include <stdio.h>  // for memset
#include <string.h> // strlen
#include <stdlib.h> // for exit
#include <errno.h>  // for errno
#include <stdarg.h> // for va_list

#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

struct pseudo_header_tcp
{
    unsigned int saddr;
    unsigned int daddr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    struct tcphdr tcph;
};

struct pseudo_header_udp
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
    struct udphdr udph;
};

static unsigned short checksum_1(const unsigned short *ptr, const int hlen)
{
    /*
     * hlen is the header you want to checksum's length
     * n means how many 16 bit there is
     */
    // 32 bits
    long sum = 0;
    /*
     * IP header 20 Bytes
     * 20 Bytes = 160 Bit = 10 * 16 Bit
     */
    int n = (hlen / 2);
    for (int i = 0; i < n; i++)
    {
        sum += *ptr;
        *ptr++;
    }

    if ((sum >> 16) != 0)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)~sum;
}

static unsigned short _csum_new(unsigned short *ptr)
{
    // 32 bits
    long sum = 0;
    /*
     * IP header 20 Bytes
     * 20 Bytes = 160 Bit = 10 * 16 Bit
     */
    int n = 10;
    for (int i = 0; i < n; i++)
    {
        sum += *ptr;
        *ptr++;
    }

    if ((sum >> 16) != 0)
    {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    return (unsigned short)~sum;
}

static unsigned short _csum(unsigned short *ptr, int nbytes)
{
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return answer;
}

/*
int main(void)
{
    char datagram[4096] = {'\0'}; // datagram to represent the packet

    struct ip *iph = (struct ip *)datagram; // IP header
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip)); // TCP header
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("192.168.2.2");

    iph->ip_v = 4;
    iph->ip_hl = 5; // header length
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
    iph->ip_id = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;                               // set to 0 before calculating checksum
    iph->ip_src.s_addr = inet_addr("192.168.2.2"); // spoof the source ip address
    iph->ip_dst.s_addr = inet_addr("192.168.2.3");

    unsigned short r1 = _csum((unsigned short *)datagram, iph->ip_len >> 1);
    unsigned short r2 = _csum_new((unsigned short *)datagram);

    tcph->source = htons("192.168.2.3");
    tcph->dest = htons(9988);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5; // TCP header length is 20 Bytes
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(65535); // maximum allowed window size
    tcph->check = 0;
    tcph->urg_ptr = 0;

    struct pseudo_header_tcp *psh = (struct pseudo_header_tcp *)malloc(sizeof(struct pseudo_header_tcp));
    psh->source_address = inet_addr("192.168.2.2");
	psh->dest_address = sin.sin_addr.s_addr;
	psh->placeholder = 0;
	psh->protocol = IPPROTO_TCP;
	psh->tcp_length = htons(20);
    memcpy(&psh->tcph, tcph, sizeof(struct tcphdr));
    unsigned short r3 = checksum_1((unsigned short *)psh, sizeof(struct pseudo_header_tcp));
    unsigned short r4 = _csum((unsigned short *)psh, sizeof(struct pseudo_header_tcp));
    free(psh);

    return 0;
}
*/


unsigned short checksum_test_udp(unsigned short *ptr, int hlen, char *data)
{
    /*
     * hlen is the header you want to checksum's length
     * n means how many 16 bit there is
     * 
     * parameters:
     *      - ptr
     *      - hlen
     *      - data
     */
    unsigned short *dptr = (unsigned short *)data;
    // 32 bits
    long sum = 0;
    int i;
    /*
     * IP header 20 Bytes
     * 20 Bytes = 160 Bit = 10 * 16 Bit
     * 20 -> 10 (20 * 1/2)
     */
    int n = (hlen >> 1);
    for (i = 0; i < n; i++)
        sum += *ptr++;
    // l         o
    // 0110 1100 0110 1111

    if (data)
    {
        n = (strlen(data) >> 1);
        for (i = 0; i < n; i++)
            sum += htons(*dptr++);
    }

    while ((sum >> 16) != 0)
        sum = (sum >> 16) + (sum & 0xffff);

    return (unsigned short)~sum;
}

int main(void)
{
    int dport = 80;
    char *daddr = "192.168.1.1";
    int sport = 3399;
    char *saddr = "192.168.1.2";
    int padding_size = 4;

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
    iph->ip_id = htons(1999);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_sum = 0; // a remplir aprés
    iph->ip_src.s_addr = inet_addr(saddr);
    iph->ip_dst.s_addr = inet_addr(daddr);
    iph->ip_sum = checksum_test_udp((unsigned short *)datagram, sizeof(struct ip), NULL);

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
        memcpy((char *)(data + i), "l", 1);
        memcpy((char *)(data + i + 1), "o", 1);
        memcpy((char *)(data + i + 2), "v", 1);
        memcpy((char *)(data + i + 3), "e", 1);
    }

    struct pseudo_header_udp *psh = (struct pseudo_header_udp *)malloc(sizeof(struct pseudo_header_udp));
    psh->source_address = inet_addr(saddr);
    psh->dest_address = sin.sin_addr.s_addr;
    psh->placeholder = 0;
    psh->protocol = IPPROTO_UDP;
    psh->udp_length = htons(size);
    memcpy(&psh->udph, udph, sizeof(struct udphdr));
    udph->uh_sum = checksum_test_udp((unsigned short *)psh, sizeof(struct pseudo_header_udp), data);
    free(psh);
}