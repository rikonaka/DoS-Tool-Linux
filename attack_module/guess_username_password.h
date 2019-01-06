#define GUESS_USERNAME_PASSWORD 0
#define SYN_FLOOD_ATTACK 1

#define USERNAME_DEFAULT "admin"
#define POST_DEFAULT 80
#define POST_DATA "user=%s&password=%s&Submit=登+陆"
#define POST_URL "http://192.168.20.1:80/login.cgi"

#define EACH_NAME_TRY 1024
#define MAX_URL_LENGTH 1024
#define MAX_POST_DATA_LENGTH 102400
#define MAX_RETURN_DATA_LENGTH 10240
#define GET_RANDOM_USERNAME 1
#define GET_RANDOM_PASSWORD 2
#define BUFFER_SIZE 1024

#define POST "POST /%s HTTP/1.1\r\n"                              \
             "HOST: %s:%d\r\n"                                    \
             "Accept: */*\r\n"                                    \
             "Content-Type:application/x-www-form-urlencoded\r\n" \
             "Content-Length: %lu\r\n\r\n"                        \
             "%s"

typedef struct attack_struct
{
    char url[MAX_URL_LENGTH];
    char post_data[MAX_POST_DATA_LENGTH];
    char return_data[MAX_RETURN_DATA_LENGTH];
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    int debug_mode;
    int attack_mode;
    /* one username set 0, use the username_list set 1 */
    int username_type;
    /* use the random password, set 0, use the password file set 1 */
    int password_type;
    struct username_list_header *username_list_header;
    struct password_list_header *password_list_header;
} AttarckStruct, *pAttarckStruct;

typedef struct username_list
{
    struct username_list *next;
    char username[MAX_USERNAME_LENGTH];
} UsernameList, *pUsernameList;

typedef struct username_list_header
{
    struct username_list *next;
    int length;
} UsernameList_Header, *pUsernameList_Header;

typedef struct password_list
{
    struct password_list *next;
    char password[MAX_PASSWORD_LENGTH];
} PasswordList, *pPasswordList;

typedef struct password_list_header
{
    struct password_list *next;
    int length;
} PasswordList_Header, *pPasswordList_Header;

int Attack_GuessUsernamePassword(const pInput process_result);