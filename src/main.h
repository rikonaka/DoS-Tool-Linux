#ifndef _MAIN_H
#define _MAIN_H

#define NON_ATTACK 0            // do nothing
#define SYN_FLOOD_ATTACK 1      // syn flood attack
#define UDP_FLOOD_ATTACK 2      // udp flood attack
#define ACK_REFLECT_ATTACK 3    // ack reflect attack
#define DNS_REFLECT_ATTACK 4    // dns reflect attack

#define ADDRESS_TYPE_IP 1
#define ADDRESS_TYPE_HTTP 2
#define ADDRESS_TYPE_HTTPS 

#define MAX_ADDRESS_LENGTH 2048              // URL
#define MAX_USERNAME_LENGTH 16
#define MAX_PASSWORD_LENGTH 16
#define MAX_ENCRYPTION_TYPE_LENGTH 16
#define MAX_USERNAME_FILE_PATH_LENGTH 100
#define MAX_PASSWORD_FILE_PATH_LENGTH 100

#define MAX_HTTP_SEND_DATA_SIZE 2048
#define MAX_HTTP_RECV_DATA_SIZE 2048

#define MAX_PROTOCOL_LENGTH 10               // http https
#define MAX_PORT_LENGTH 6                   // 65535

#define ENABLE 1
#define DISABLE 0

#define TRUE 1
#define FALSE 0

#define PROCESS_NUM_DEFAULT 1
#define THREAD_NUM_DEFAULT 4

#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443

/* need re-think here */
#define ACK_IP_LIST_NAME "./core_module/ack_reflect_ip_list.txt"
#define DNS_IP_LIST_NAME "./core_module/dns_reflect_ip_list.txt"

// if you want to change this name, please also edit the dns query->name size
#define DNS_QUERY_NAME_DEFAULT "github.com"

// for UDP padding size
// make sure the size is very small
// same traffic will send more packages that make the target busy
#define PADDING_SIZE 1

typedef struct udp_struct
{
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
    size_t each_ip_repeat;
} UDPStruct, *pUDPStruct;

// defined by str.h


typedef struct str_node
{
    struct str_node *next;
    int label; // if label == 0, this node's value is not used
    char *str;
} StrNode, *pStrNode;

typedef struct str_header
{
    struct str_node *next;
    size_t length;

    /* 
     * NORMAL_STR_LIST_MODE: get the str from the file
     *                       and put it into a list
     * REPEAT_STR_LIST_MODE: repeat one str in user
     * RANDOM_STR_LIST_MODE: specify this str should
     *                       be random string
     */
    int str_list_mode;

    /* 
     * USERNAME_STR_LIST: this string list store the username
     * PASSWORD_STR_LIST: this string list store the password
     */
    int str_list_type;
    struct str_node *cursor; // this pointer will point to the next not used value
} StrHeader, *pStrHeader;


typedef struct ip_list_thread
{
    struct ip_list_thread *next;
    pStrHeader list;
} IPList_Thread, *pIPList_Thread;

typedef struct pseudo_header
{
    // Needed for checksum calculation
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
    // struct tcphdr tcp;
} PseudoHeader;

typedef struct syn_flood_st
{
    int random_saddr;
    long int ip_repeat_time;
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
} SynFloodSt, *pSynFloodSt;

typedef struct parameter
{
    int attack_mode;

    long int thread_num;
    /* if 0, ip address */
    /* if 1, http url address */
    /* if 2, https url address */
    int address_type;

    /* for brute force atack user */

    char *target_address;
    int target_port;

    /* field in the thread program */
    int seed;
    pSynFloodSt _syn_flood_st;
} Parameter, *pParameter;

#endif