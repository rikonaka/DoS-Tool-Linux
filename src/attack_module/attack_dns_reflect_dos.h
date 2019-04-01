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

// constant sized fields of the resource record structure
typedef struct r_data
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} RData, *pRData;

// pointers to resource record contents
typedef struct res_record
{
    unsigned char *name;
    struct r_data *resource;
    unsigned char *rdata;
} ResRecord, *pResRecord;

// structure of a Query
typedef struct query
{
    unsigned char *name;
    struct question *ques;
} Query, *pQuery;

// constant sized fields of query structure
typedef struct question
{
    unsigned short qtype;
    unsigned short qclass;
} Question, *pQuestion;

// DNS header structure
typedef struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd : 1;     // recursion desired
    unsigned char tc : 1;     // truncated message
    unsigned char aa : 1;     // authoritive answer
    unsigned char opcode : 4; // purpose of message
    unsigned char qr : 1;     // query/response flag

    unsigned char rcode : 4; // response code
    unsigned char cd : 1;    // checking disabled
    unsigned char ad : 1;    // authenticated data
    unsigned char z : 1;     // its z! reserved
    unsigned char ra : 1;    // recursion available

    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
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