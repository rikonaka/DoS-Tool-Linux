#ifndef _MAIN_H
#define _MAIN_H

// 0 - guess the web passwd (advanced, not point now)
// 1 - syn flood attack
// 2 - udp flood attack
#define GUESS 0
#define SYN_FLOOD_ATTACK 1
#define UDP_FLOOD_ATTACK 2

// username from one string and password from linked list
#define GUESS_U1PL 0
// username from one string buf password from random generate
#define GUESS_U1PR 1
// list and list
#define GUESS_ULPL 2
// get the return value length
#define GUESS_GET_RESPONSE_LENGTH 3
// use the response length judge the password is right or not
#define GUESS_LENGTH 4

#define DISABLE_SIP 0
#define ENABLE_SIP 1

#define DEBUG_OFF 0
#define DEBUG_LEVEL_1 1 // show the importance value
#define DEBUG_LEVEL_2 2 // show the not importance value
#define DEBUG_LEVEL_3 3 // show function start, end

#define MAX_USERNAME_LENGTH 16
#define MAX_PASSWORD_LENGTH 16
#define MAX_USERNAME_PATH_LENGTH 100
#define MAX_PASSWORD_PATH_LENGTH 100
#define MAX_URL_LENGTH 50
#define MAX_MODEL_TYPE_LENGTH 20
#define COMMON_BUFFER_SIZE 16
#define SEND_DATA_SIZE 2048
#define RECEIVE_DATA_SIZE 2048
#define IP_BUFFER_SIZE 20

#define ATTACK_MODE_DEFAULT 1
#define DEBUG_LEVEL_DEFAULT 0 // DEBUG_OFF
#define PROCESS_NUM_DEFAULT 1
#define THREAD_NUM_DEFAULT 8
#define RANDOM_PASSWORD_LENGTH_DEFAULT 8
#define RANDOM_SIP_DEFAULT 1 // default open it for attack safety
#define USERNAME_DEFAULT "admin"
#define RECV_TIME_OUT 99 // s
#define MODEL_TYPE_DEFAULT "feixun_fwr_604h"
#define HTTP_PORT_DEFAULT 80
#define HTTPS_PORT_DEFAULT 443
#define EACH_IP_REPEAT_TIME 10240
#define SYN_FLOOD_PORT_DEFAULT 80

#define TEST_TYPE_NON 0
#define TEST_TYPE_GUESS -1
#define TEST_TYPE_SYN_FLOOD -2
#define TEST_TYPE_UDP_FLOOD -3

#define DEFAULT_ADDRESS "192.168.99.99"
#define DEFAULT_PORT 9999

#define ENABLE 1
#define DISABLE 0

// defined by str.h
typedef struct split_url_output
{
    char *protocol;
    char *host;
    int port;
    char *suffix;
} SplitURLOutput, *pSplitURLOutput;

typedef struct str_node
{
    struct str_node *next;
    char *str;
} StrNode, *pStrNode;

typedef struct str_header
{
    struct str_node *next;
    size_t length;
} StrHeader, *pStrHeader;

typedef struct guess_attack_use
{
    // if not use the path file, set NULL
    struct str_header *u_header;
    struct str_header *p_header;
} GuessAttackUse, *pGuessAttackUse;

typedef struct thread_control_node
{
    struct thread_control_node *next;
    unsigned long tid; // typedef unsigned long pthread_t
    int id;
} ThreadControlNode, *pThreadControlNode;

typedef struct thread_control_header
{
    struct thread_control_node *next;
    size_t length;
} ThreadControlHeader, *pThreadControlHeader;

typedef struct user_input
{
    // has the defalut value
    int attack_mode;
    int random_password_length;
    int random_sip_address;
    int debug_level;
    int max_process;
    int max_thread;
    int each_ip_repeat;
    // 0 is not test
    // -1 is guess
    // -2 is syn flood
    int test_type;
    // field with program
    int seed;
    pThreadControlHeader tch;
    int guess_attack_type;
    struct guess_attack_use *gau;
    // int serial_num;
    // didn't have defalut value and not field with program
    int get_response_length;
    int watch_length;
    // char value
    char address[MAX_URL_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char username_path[MAX_USERNAME_PATH_LENGTH];
    char password_path[MAX_PASSWORD_PATH_LENGTH];
    char model_type[MAX_MODEL_TYPE_LENGTH];
    // coming soon
} Input, *pInput;

#endif