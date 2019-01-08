#ifndef _GUESS_USERNAME_PASSWORD_H
#define _GUESS_USERNAME_PASSWORD_H

#define GUESS_USERNAME_PASSWORD 0
#define SYN_FLOOD_ATTACK 1

#define GET_RANDOM_USERNAME 1
#define GET_RANDOM_PASSWORD 2

#define EACH_NAME_TRY 1024

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

#endif