#ifndef _MAIN_H
#define _MAIN_H

// 0  - guess the web passwd (advanced)
// 1  - syn flood attack
#define GUESS_USERNAME_PASSWORD 0
#define SYN_FLOOD_ATTACK 1

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
#define MAX_URL_LENGTH 100
#define MAX_MODEL_TYPE_LENGTH 20
#define COMMON_BUFFER_SIZE 16
#define SEND_DATA_SIZE 2048
#define RECEIVE_DATA_SIZE 2048

#define ATTACK_MODE_DEFAULT 1
#define DEBUG_LEVEL_DEFAULT 0 // DEBUG_OFF
#define PROCESS_NUM_DEFAULT 4
#define THREAD_NUM_DEFAULT 2
#define RANDOM_PASSWORD_LENGTH_DEFAULT 8
#define RANDOM_SIP_DEFAULT 1 // default open it for attack safety
#define PORT_DEFAULT 80
#define USERNAME_DEFAULT "admin"
#define RECV_TIME_OUT 9 // s
#define MODEL_TYPE_DEFAULT "not_sure"

#define ENABLE 0
#define DISABLE -1

typedef struct user_input
{
    // has the defalut value
    int attack_mode;
    int random_password_length;
    int random_sip_address;
    int debug_level;
    int max_process;
    int max_thread;
    // field with program
    int seed;
    int serial_num;
    int guess_attack_type;
    struct guess_attack_use *gau;
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

// defined by str.h
typedef struct split_url_output
{
    char *host;
    char *suffix;
    int port;
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

#endif