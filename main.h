#ifndef _MAIN_H
#define _MAIN_H

/*
    0  - guess the web passwd (advanced)
    1  - syn flood attack
*/
#define ATTACK_MODE_DEFAULT 1

#define MAX_USERNAME_LENGTH 10
#define MAX_PASSWORD_LENGTH 20
#define MAX_USERNAME_PATH_LENGTH 100
#define MAX_PASSWORD_PATH_LENGTH 100
#define MAX_URL_LENGTH 100
#define MAX_SEND_DATA_SIZE 10240
#define MAX_RECEIVE_DATA_SIZE 10240
#define SMALL_BUFFER_SIZE 128
#define BIG_BUFFER_SIZE 1024

#define DEBUG_LEVEL_DEFAULT 0 // DEBUG_OFF
#define PROCESS_NUM_DEFAULT 4
#define THREAD_NUM_DEFAULT 2
#define RANDOM_PASSWORD_LENGTH_DEFAULT 8
#define RANDOM_SIP_DEFAULT 1 // default open it for attack safety
#define PORT_DEFAULT 80
#define USERNAME_DEFAULT "admin"

//#define POST_DATA "user=%s&password=%s&Submit=登+陆"
//#define POST_URL "http://192.168.20.1:80/login.cgi"

typedef struct attack_struct
{
    char url[MAX_URL_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int debug_level;
    int attack_mode;
    /* one username set 0, use the username_list set 1 */
    int username_type;
    /* use the random password, set 0, use the password file set 1 */
    int password_type;
    struct username_list_header *username_list_header;
    struct password_list_header *password_list_header;
} AttarckStruct, *pAttarckStruct;

typedef struct input
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

#endif