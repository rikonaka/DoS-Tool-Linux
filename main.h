#ifndef _MAIN_H
#define _MAIN_H

/*
    0  - guess the web passwd (advanced)
    1  - syn flood attack
*/
#define GUESS_USERNAME_PASSWORD 0
#define SYN_FLOOD_ATTACK 1
#define ATTACK_MODE_DEFAULT 1

#define DEBUG_OFF 0
#define DEBUG_LEVEL_1 1 // show the importance value
#define DEBUG_LEVEL_2 2 // show the not importance value
#define DEBUG_LEVEL_3 3 // show function start, end
#define MAX_LOG_BUF_SIZE 50

#define MAX_USERNAME_LENGTH 16
#define MAX_PASSWORD_LENGTH 16
#define MAX_USERNAME_PATH_LENGTH 100
#define MAX_PASSWORD_PATH_LENGTH 100
#define MAX_URL_LENGTH 100
#define MAX_SEND_DATA_SIZE 1024
#define MAX_RECEIVE_DATA_SIZE 1024
#define SMALL_BUFFER_SIZE 128
#define BIG_BUFFER_SIZE 1024

#define DEBUG_LEVEL_DEFAULT 0 // DEBUG_OFF
#define PROCESS_NUM_DEFAULT 4
#define THREAD_NUM_DEFAULT 2
#define RANDOM_PASSWORD_LENGTH_DEFAULT 8
#define RANDOM_SIP_DEFAULT 1 // default open it for attack safety
#define PORT_DEFAULT 80
#define USERNAME_DEFAULT "admin"
#define RECV_TIME_OUT 20 // s

typedef struct user_input
{
    int attack_mode;
    int debug_level;
    int max_process;
    int max_thread;
    int seed;
    int random_password_length;
    int random_sip_address;
    char address[MAX_URL_LENGTH];
    char attack_mode_0_one_username[MAX_USERNAME_LENGTH];
    char attack_mode_0_username_file_path[MAX_USERNAME_PATH_LENGTH];
    char attack_mode_0_password_file_path[MAX_PASSWORD_PATH_LENGTH];
    // continue
} Input, *pInput;

// defined by str.h
typedef struct split_url_output
{
    char *host;
    char *suffix;
    int port;
} SplitURLOutput, *pSplitURLOutput;

typedef struct char_node
{
    struct char_node *next;
    char *username;
} CharNode, *pCharNode;

typedef struct char_header
{
    struct char_node *next;
    size_t length;
} CharHeader, *pCharHeader;

#endif