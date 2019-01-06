#define GUESS_USERNAME_PASSWORD 0
#define SYN_FLOOD_ATTACK 1

#define USERNAME_DEFAULT "admin"
#define EACH_NAME_TRY 1024

typedef struct attack_post_struct
{
    char *url;
    char *post_data;
    char *return_str;
    int debug_mode;
    int attack_mode;
} AttarckPostStruct, *pAttarckPostStruct;

typedef struct username_list
{
    struct username_list *next;
    char username[MAX_USERNAME_LENGTH];
} UsernameList, *pUsernameList;

int Attack_GuessUsernamePassword(const pInput process_result);