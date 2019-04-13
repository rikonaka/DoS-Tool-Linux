#ifndef _ATTACK_DNS_REFLECT_DOS_H
#define _ATTACK_DNS_REFLECT_DOS_H

// yypes of DNS resource records :)
// query type is here
#define T_A 1     // ipv4 address
#define T_NS 2    // nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6   // start of authority zone
#define T_PTR 12  // domain name pointer
#define T_MX 15   // mail server

#define DNS_QUERY_TYPE_DEFAULT T_A
#define DNS_SIZE 4096

// constant sized fields of the resource record structure
typedef struct r_data
{
    unsigned short int type;
    unsigned short int _class;
    unsigned int ttl;
    unsigned short int data_len;
} RData, *pRData;

// pointers to resource record contents
typedef struct res_record
{
    unsigned char *name;
    struct r_data *resource;
    unsigned char *rdata;
} ResRecord, *pResRecord;

typedef struct dns_name
{
    unsigned short int len;
    char name_part;
} DNSName, *pDNSName;

// structure of a Query
typedef struct query
{
    //           012345678901
    // test name 6github3com0
    char name;
    struct question *question;
} Query, *pQuery;

typedef struct question
{
    unsigned short int qtype;
    unsigned short int qclass;
} Question, *pQuestion;

// DNS header structure
typedef struct dns_header
{
    unsigned short int id; // identification number

    // flag
    // unsigned short int == uint16_t
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned short int qr : 1;
    unsigned short int opcode : 4;
    unsigned short int aa : 1;
    unsigned short int tc : 1;
    unsigned short int rd : 1;
    unsigned short int ra : 1;
    unsigned short int z : 3;
    unsigned short int rcode : 4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short int rd : 1;
    unsigned short int tc : 1;
    unsigned short int aa : 1;
    unsigned short int opcode : 4;
    unsigned short int qr : 1;
    unsigned short int rcode : 4;
    unsigned short int z : 3;
    unsigned short int ra : 1;
#endif

    unsigned short qcount;  // question count
    unsigned short ancount; // answer record count
    unsigned short nscount; // name server count
    unsigned short adcount; // additional record count

} DNSHeader, *pDNSHeader;

// for attack use
typedef struct dns_struct
{
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
    size_t each_ip_repeat;
    size_t debug_level;
    pStrHeader str_header;
} DNSStruct, *pDNSStruct;

#endif