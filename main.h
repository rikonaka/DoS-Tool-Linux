/*
    0  - guess the web passwd (advanced)
    1  - syn flood attack
*/
#define ATTACK_MODE_DEFAULT 1

/*
    0 - do not show the debug information
    1 - show the debug information
    2 - more debug information
*/
#define DEBUG_MODE_DEFAULT 0

#define MAX_USERNAME_LENGTH 10
#define MAX_PASSWORD_LENGTH 20
#define MAX_USERNAME_PATH_LENGTH 100
#define MAX_PASSWORD_PATH_LENGTH 100

typedef struct input
{
    int attack_mode;
    int debug_mode;
    char attack_mode_0_one_username[MAX_USERNAME_LENGTH];
    char attack_mode_0_one_password[MAX_PASSWORD_LENGTH];
    char attack_mode_0_username_file_path[MAX_USERNAME_PATH_LENGTH];
    char attack_mode_0_password_file_path[MAX_PASSWORD_PATH_LENGTH];
    // continue
} Input, *pInput;